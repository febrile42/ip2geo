<?php
/**
 * Per-client-IP lookup rate limit (APCu), shared by api/lookup.php and
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
 *
 * <key> is rate_limit_key($clientIp): the IPv4 address as is, or the /64
 * prefix for IPv6 (IPG-21), since one IPv6 client usually holds a whole /64
 * and could otherwise take a fresh bucket per request. <window> is
 * intdiv(now, window seconds), so a new window is a new key and the reset
 * never depends on APCu expiring anything. The TTL on the entry is only
 * there to free memory.
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
 * with anything else.
 *
 * Fails open without APCu (documented decision): a box without it never
 * blocks lookups outright.
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
 * The client identity a rate-limit bucket is keyed on (IPG-21). IPv4 comes
 * back unchanged; IPv4-mapped IPv6 (::ffff:a.b.c.d) is treated as that IPv4;
 * any other IPv6 address becomes its /64, e.g. '2001:db8:1:2::/64'.
 * Anything that isn't an IP (shouldn't happen for REMOTE_ADDR) is returned
 * as is, so it still gets its own bucket.
 *
 * Residual (accepted): a client holding many /64s, e.g. a /48, still gets
 * one bucket per /64.
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
    return inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
}

/**
 * Default rate limiter: charges $cost units to this client's bucket for the
 * current window and reports whether the window's budget is now exceeded.
 * Gracefully returns "not limited" if APCu isn't loaded.
 *
 * @param ?callable $increment function(string $key, int $step, int $ttl): int|false,
 *                             defaults to apcu_inc(); injectable so tests can
 *                             model APCu without the extension
 * @param ?int      $now       unix time, defaults to time()
 *
 * @return array{limited: bool, retry_after: int}
 */
function default_lookup_rate_limiter(
    string $clientIp,
    string $bucket = LOOKUP_RATE_BUCKET_API,
    int $cost = 1,
    ?callable $increment = null,
    ?int $now = null
): array {
    if ($increment === null) {
        if (!function_exists('apcu_inc')) {
            return ['limited' => false, 'retry_after' => 0];
        }
        $increment = static function (string $key, int $step, int $ttl) {
            return apcu_inc($key, $step, $success, $ttl);
        };
    }
    if ($clientIp === '') {
        return ['limited' => false, 'retry_after' => 0];
    }

    $now    = $now ?? time();
    $window = LOOKUP_RATE_LIMIT_WINDOW_SECONDS;
    $key    = $bucket . ':' . rate_limit_key($clientIp) . ':' . intdiv($now, $window);
    $count  = $increment($key, max(1, $cost), $window);

    if ($count !== false && $count > LOOKUP_RATE_LIMIT_MAX) {
        return ['limited' => true, 'retry_after' => $window - ($now % $window)];
    }

    return ['limited' => false, 'retry_after' => 0];
}
