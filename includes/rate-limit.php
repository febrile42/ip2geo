<?php
/**
 * Per-client-IP lookup rate limit (APCu), shared by api/lookup.php and
 * index.php's no-JS POST path (IPG-17).
 *
 * Buckets: each entry point has its own APCu key prefix, so the limit is
 * 60 requests/minute per client IP *per path*:
 *
 *   api/lookup.php      'lookup_rate:<ip>'       (LOOKUP_RATE_BUCKET_API)
 *   index.php POST /    'lookup_rate_nojs:<ip>'  (LOOKUP_RATE_BUCKET_NOJS)
 *
 * Separate buckets because a real visitor only ever uses one of the two (JS
 * on or off), and it keeps the CI functional + perf POSTs to / (two per
 * deploy, from one runner IP straight to the origin) from ever competing
 * with anything else. Each request on either path is capped at 10k IPs, so
 * the worst case per IP is the same on both.
 *
 * Fails open without APCu (documented decision): a box without it never
 * blocks lookups outright.
 */

declare(strict_types=1);

// 60 requests/minute is this lane's assumption, not a design-doc number —
// cheap to retune later since it's isolated to these two constants.
if (!defined('LOOKUP_RATE_LIMIT_MAX')) {
    define('LOOKUP_RATE_LIMIT_MAX', 60);
}
if (!defined('LOOKUP_RATE_LIMIT_WINDOW_SECONDS')) {
    define('LOOKUP_RATE_LIMIT_WINDOW_SECONDS', 60);
}

const LOOKUP_RATE_BUCKET_API  = 'lookup_rate';
const LOOKUP_RATE_BUCKET_NOJS = 'lookup_rate_nojs';

/**
 * Default rate limiter: the APCu increment-then-add-fallback pattern from
 * get-report.php:41-54, keyed per client IP instead of per free-report
 * token. Gracefully returns "not limited" if APCu isn't loaded (matches
 * get-report.php's function_exists guard).
 *
 * @return array{limited: bool, retry_after: int}
 */
function default_lookup_rate_limiter(string $clientIp, string $bucket = LOOKUP_RATE_BUCKET_API): array
{
    if (!function_exists('apcu_inc') || $clientIp === '') {
        return ['limited' => false, 'retry_after' => 0];
    }

    $key     = $bucket . ':' . $clientIp;
    $success = false;
    $count   = apcu_inc($key, 1, $success);
    if (!$success) {
        if (!apcu_add($key, 1, LOOKUP_RATE_LIMIT_WINDOW_SECONDS)) {
            $count = apcu_inc($key) ?: 1;
        } else {
            $count = 1;
        }
    }

    if ($count > LOOKUP_RATE_LIMIT_MAX) {
        return ['limited' => true, 'retry_after' => LOOKUP_RATE_LIMIT_WINDOW_SECONDS];
    }

    return ['limited' => false, 'retry_after' => 0];
}
