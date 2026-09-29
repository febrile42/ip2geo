<?php
/**
 * Lookup rate limit (APCu), per client IP and across all clients, shared by api/lookup.php and
 * index.php's no-JS POST path (IPG-17).
 *
 * Budget, not request count (IPG-48): each client gets
 * LOOKUP_RATE_LIMIT_MAX cost units per fixed LOOKUP_RATE_LIMIT_WINDOW_SECONDS
 * window *per path*, and a request costs lookup_rate_cost($ipCount) units
 * (1, plus 1 per full 1,000 IPs: 1 for anything under 1,000, 11 for a full
 * 10k lookup). That lets many small lookups from one address through (a SOC
 * behind one NAT egress all opening the same #v= share link, ≤ ~1,500 IPs
 * each) while a client sending max-size lookups is held to about the same
 * work per minute as the old flat 60 requests/minute.
 *
 *   api/lookup.php      'lookup_rate:<key>:<window>'       (LOOKUP_RATE_BUCKET_API)
 *   index.php POST /    'lookup_rate_nojs:<key>:<window>'  (LOOKUP_RATE_BUCKET_NOJS)
 *   all clients         '<bucket>_global:<window>'         (LOOKUP_RATE_GLOBAL_MAX_*)
 *
 * <key> is rate_limit_key($clientIp): the IPv4 address as is, or the /56
 * prefix for IPv6 (IPG-145, was /64 in IPG-21), since one IPv6 client
 * usually holds at least a /64 and often a /56, and could otherwise take a
 * fresh bucket per request. <window> is intdiv(now, window seconds), so a
 * new window is a new key and the reset never depends on APCu expiring
 * anything. The TTL on the entry is only there to free memory.
 *
 * Global ceiling (IPG-145): on top of the per-client budget, each path has
 * one budget shared by every client, 'lookup_rate_global:<window>' and
 * 'lookup_rate_nojs_global:<window>'. Per-client limits don't help against
 * many addresses (proxy pools, many /56s), and about 4 clients at the
 * per-client budget saturate a core on the one box prod and staging share.
 * A request is charged to the global budget only once its client budget
 * lets it through, so a single client that is already limited can't drain
 * it for everyone. Over the ceiling the answer is a 429 like the
 * per-client one, with reason 'global'.
 *
 * Why not the old apcu_inc-then-apcu_add pattern (from get-report.php):
 * apcu_inc() inserts a missing key itself, with its $ttl argument (default
 * 0 = never expires), and reports success, so the apcu_add(…, 60) fallback
 * never ran. Every counter lived until APCu restarted and "60/minute" was
 * really "60 ever" per client, locking out whole offices behind one IP.
 *
 * Separate buckets because a real visitor only ever uses one of the two (JS
 * on or off), and it keeps the CI functional + perf POSTs to / (two per
 * deploy, from one runner IP straight to the origin) from ever competing
 * with anything else. The same goes for the global budgets: a flood on one
 * path leaves the other one working.
 *
 * Fails closed without APCu (IPG-145, was fail-open): if APCu isn't loaded
 * or is disabled, every lookup gets a 503 and error_log() says why, so a
 * PHP upgrade that drops the extension can't silently turn the limiter off.
 * The deploy workflow checks /api/lookup.php answers 200 after each deploy.
 * A store error on an individual increment (apcu_inc() returning false)
 * still lets that request through.
 */

declare(strict_types=1);

// Cost units per client per window. Measured on staging (IPG-48): a 10k
// no-JS lookup is ~0.3s server time, a 1-IP lookup well under 0.06s.
if (!defined('LOOKUP_RATE_LIMIT_MAX')) {
    define('LOOKUP_RATE_LIMIT_MAX', 600);
}
if (!defined('LOOKUP_RATE_LIMIT_WINDOW_SECONDS')) {
    define('LOOKUP_RATE_LIMIT_WINDOW_SECONDS', 60);
}
// Cost units per window across all clients, per path (IPG-145). Sized to
// about 0.7 of one core at the worst case of every request being a full
// 10k lookup (11 units, ~0.3s): 1,500 units ≈ 136 max-size lookups ≈ 41s
// of CPU a minute. Most of it goes to the API, which the web UI uses; the
// no-JS path is rare and every POST there costs a full 11 units.
if (!defined('LOOKUP_RATE_GLOBAL_MAX_API')) {
    define('LOOKUP_RATE_GLOBAL_MAX_API', 1200);
}
if (!defined('LOOKUP_RATE_GLOBAL_MAX_NOJS')) {
    define('LOOKUP_RATE_GLOBAL_MAX_NOJS', 300);
}
// IPs per cost unit above the first.
const LOOKUP_RATE_IPS_PER_UNIT = 1000;

const LOOKUP_RATE_BUCKET_API  = 'lookup_rate';
const LOOKUP_RATE_BUCKET_NOJS = 'lookup_rate_nojs';

/**
 * Cost units for one lookup of $ipCount unique IPs: 1 for 0–999, 2 for
 * 1,000–1,999, … 11 for 10,000.
 */
function lookup_rate_cost(int $ipCount): int
{
    return 1 + intdiv(max(0, $ipCount), LOOKUP_RATE_IPS_PER_UNIT);
}

/**
 * The client identity a rate-limit bucket is keyed on (IPG-21, IPG-145).
 * IPv4 comes back unchanged; IPv4-mapped IPv6 (::ffff:a.b.c.d) is treated
 * as that IPv4; any other IPv6 address becomes its /56, e.g.
 * '2001:db8:1:200::/56'. Anything that isn't an IP (shouldn't happen for
 * REMOTE_ADDR) is returned as is, so it still gets its own bucket.
 *
 * Residual (accepted): a client holding a /48 still gets 256 buckets; the
 * global ceiling is what bounds that.
 */
function rate_limit_key(string $ip): string
{
    $packed = @inet_pton($ip);
    if ($packed === false || strlen($packed) !== 16) {
        return $ip;
    }
    if (strncmp($packed, str_repeat("\0", 10) . "\xff\xff", 12) === 0) {
        return (string) inet_ntop(substr($packed, 12));
    }
    return inet_ntop(substr($packed, 0, 7) . str_repeat("\0", 9)) . '/56';
}

/** The global (all clients) cost ceiling per window for $bucket. */
function lookup_rate_global_max(string $bucket): int
{
    return $bucket === LOOKUP_RATE_BUCKET_NOJS ? LOOKUP_RATE_GLOBAL_MAX_NOJS : LOOKUP_RATE_GLOBAL_MAX_API;
}

/**
 * apcu_inc() as the limiter's increment, or null if APCu isn't loaded or
 * is disabled (apc.enabled=0, or the CLI without apc.enable_cli).
 *
 * @return ?callable function(string $key, int $step, int $ttl): int|false
 */
function lookup_rate_apcu_increment(): ?callable
{
    if (!function_exists('apcu_inc') || !function_exists('apcu_enabled') || !apcu_enabled()) {
        return null;
    }
    return static function (string $key, int $step, int $ttl) {
        return apcu_inc($key, $step, $success, $ttl);
    };
}

/**
 * The limiter itself: charges $cost units to this client's bucket for the
 * current window, then (if the client is still within budget) to the
 * path's global bucket, and reports the first budget that is exceeded.
 *
 * $reason is 'client' or 'global' when limited (both are 429s), and
 * 'unavailable' when $increment is null, i.e. there is no store to count
 * in: the lookup is refused (503) rather than let through unmetered.
 *
 * @param ?callable $increment function(string $key, int $step, int $ttl): int|false,
 *                             null when no store is available
 *
 * @return array{limited: bool, retry_after: int, reason: string}
 */
function lookup_rate_check(string $clientIp, string $bucket, int $cost, ?callable $increment, int $now): array
{
    $window     = LOOKUP_RATE_LIMIT_WINDOW_SECONDS;
    $retryAfter = $window - ($now % $window);

    if ($increment === null) {
        error_log('ip2geo rate limit: APCu is not loaded or not enabled; refusing lookups (fails closed, IPG-145)');
        return ['limited' => true, 'retry_after' => $retryAfter, 'reason' => 'unavailable'];
    }

    $cost = max(1, $cost);
    $slot = intdiv($now, $window);

    if ($clientIp !== '') {
        $count = $increment($bucket . ':' . rate_limit_key($clientIp) . ':' . $slot, $cost, $window);
        if ($count !== false && $count > LOOKUP_RATE_LIMIT_MAX) {
            return ['limited' => true, 'retry_after' => $retryAfter, 'reason' => 'client'];
        }
    }

    $count = $increment($bucket . '_global:' . $slot, $cost, $window);
    if ($count !== false && $count > lookup_rate_global_max($bucket)) {
        return ['limited' => true, 'retry_after' => $retryAfter, 'reason' => 'global'];
    }

    return ['limited' => false, 'retry_after' => 0, 'reason' => ''];
}

/**
 * Default rate limiter for both lookup paths: lookup_rate_check() against
 * APCu, now.
 *
 * @param ?callable $increment defaults to lookup_rate_apcu_increment();
 *                             injectable so tests can model APCu without
 *                             the extension
 * @param ?int      $now       unix time, defaults to time()
 *
 * @return array{limited: bool, retry_after: int, reason: string}
 */
function default_lookup_rate_limiter(
    string $clientIp,
    string $bucket = LOOKUP_RATE_BUCKET_API,
    int $cost = 1,
    ?callable $increment = null,
    ?int $now = null
): array {
    return lookup_rate_check($clientIp, $bucket, $cost, $increment ?? lookup_rate_apcu_increment(), $now ?? time());
}
