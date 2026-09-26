<?php
/**
 * JSON lookup endpoint: POST application/json {"ips": [...], "counts": {...}?}
 *
 * The client (browser extraction, per R4/S1) sends deduped IPs; this endpoint
 * re-validates, caps, rate-limits, looks up via includes/lookup.php's
 * lookup_ips(), and classifies each hit the same way the HTML page does
 * (classify_asn + Spamhaus DROP, IPv4 only).
 *
 *   POST body (raw, ≤ 2 MB) ──▶ [size check]  > 2 MB ──────────▶ 413
 *          │
 *          ▼
 *   JSON decode, dedupe "ips" ──▶ [count check] > 10,000 unique ▶ 413
 *          │
 *          ▼
 *   client IP (CF-Connecting-IP if REMOTE_ADDR is a Cloudflare edge, else REMOTE_ADDR)
 *          │
 *          ▼
 *   [rate limit check, APCu]  ──▶ limited ───────────────────────▶ 429
 *          │                                                       (Retry-After header)
 *          ▼  not limited (or APCu unavailable: skipped, never blocks)
 *   split ips: valid (filter_var FILTER_VALIDATE_IP) / unresolved (rest)
 *          │
 *          ▼
 *   lookup_ips(valid)  ──▶ .mmdb missing/corrupt (GeoDbUnavailableException) ▶ 503
 *          │                                                       (never logs the body;
 *          │                                                        error_log gets counts only)
 *          ▼
 *   classify_asn() + ip_in_spamhaus_drop() (IPv4 only; v6 rows get drop=false)
 *          │
 *          ▼
 *   200  {"results": [{ip, country_iso_code, country_name, subdivision_1_name,
 *                       city_name, autonomous_system_number, autonomous_system_org,
 *                       category, drop}, ...],
 *         "unresolved": ["<ips that failed FILTER_VALIDATE_IP>", ...]}
 *
 * Request bodies are never written to error_log or any other log — only
 * counts (e.g. "N IPs requested") ever appear in error messages.
 */

declare(strict_types=1);

require_once __DIR__ . '/../includes/lookup.php';
require_once __DIR__ . '/../asn_classification.php';
require_once __DIR__ . '/../report_functions.php'; // ip_in_spamhaus_drop()

// Cap on unique IPs per request and on raw body size.
if (!defined('LOOKUP_MAX_UNIQUE_IPS')) {
    define('LOOKUP_MAX_UNIQUE_IPS', 10000);
}
if (!defined('LOOKUP_MAX_BODY_BYTES')) {
    define('LOOKUP_MAX_BODY_BYTES', 2 * 1024 * 1024); // 2 MB
}

// Per-client-IP rate limit (APCu). Not specified by the design doc beyond
// "rate limit per client IP using the APCu pattern from get-report.php";
// 60 requests/minute is this lane's assumption — cheap to retune later
// since it's isolated to these two constants.
if (!defined('LOOKUP_RATE_LIMIT_MAX')) {
    define('LOOKUP_RATE_LIMIT_MAX', 60);
}
if (!defined('LOOKUP_RATE_LIMIT_WINDOW_SECONDS')) {
    define('LOOKUP_RATE_LIMIT_WINDOW_SECONDS', 60);
}

/**
 * Convert an IPv4 string to its unsigned 32-bit int form for
 * ip_in_spamhaus_drop(), which is IPv4-only. Mirrors index.php's ipToLong()
 * (kept local here since we don't require index.php — that would execute
 * the whole HTML page). Returns null for IPv6 or unparseable input, which
 * callers must treat as "not in DROP" (drop = false), per R4's scope note.
 */
function lookup_endpoint_ip4_to_uint(string $ip): ?int
{
    $long = ip2long($ip);
    if ($long === false) {
        return null;
    }
    return (int)sprintf('%u', $long);
}

/**
 * Default rate limiter: the APCu increment-then-add-fallback pattern from
 * get-report.php:41-54, keyed per client IP instead of per free-report
 * token. Gracefully returns "not limited" if APCu isn't loaded (matches
 * get-report.php's function_exists guard) so a box without APCu never
 * blocks lookups outright.
 *
 * @return array{limited: bool, retry_after: int}
 */
function default_lookup_rate_limiter(string $clientIp): array
{
    if (!function_exists('apcu_inc') || $clientIp === '') {
        return ['limited' => false, 'retry_after' => 0];
    }

    $key     = 'lookup_rate:' . $clientIp;
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

// Cloudflare's published edge ranges (https://www.cloudflare.com/ips/,
// fetched 2026-09-26). CF-Connecting-IP is only trusted when the request
// actually came from one of these; anything else hit the origin directly and
// could put any value in that header. Cloudflare changes this list rarely;
// re-check it when touching this file.
if (!defined('CLOUDFLARE_IP_RANGES')) {
    define('CLOUDFLARE_IP_RANGES', [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ]);
}

/** True if $ip (v4 or v6) is inside $cidr. Mismatched families never match. */
function lookup_endpoint_ip_in_cidr(string $ip, string $cidr): bool
{
    [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
    $ipBin  = @inet_pton($ip);
    $netBin = @inet_pton((string)$net);
    if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
        return false;
    }
    $maxBits = strlen($ipBin) * 8;
    $bits    = $bits === null ? $maxBits : (int)$bits;
    if ($bits < 0 || $bits > $maxBits) {
        return false;
    }
    $bytes = intdiv($bits, 8);
    if (substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
}

function lookup_endpoint_is_cloudflare(string $ip): bool
{
    foreach (CLOUDFLARE_IP_RANGES as $cidr) {
        if (lookup_endpoint_ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * Client IP for rate limiting. CF-Connecting-IP only when REMOTE_ADDR is a
 * Cloudflare edge and the header holds a valid IP; otherwise REMOTE_ADDR,
 * so a direct-to-origin caller can't mint a fresh rate-limit bucket per
 * request by varying the header.
 */
function lookup_endpoint_client_ip(array $server): string
{
    $remote = trim((string)($server['REMOTE_ADDR'] ?? ''));
    $cf     = trim((string)($server['HTTP_CF_CONNECTING_IP'] ?? ''));
    if ($cf !== '' && lookup_endpoint_is_cloudflare($remote) && filter_var($cf, FILTER_VALIDATE_IP) !== false) {
        return $cf;
    }
    return $remote;
}

function lookup_endpoint_json_error(int $status, string $message, array $extraHeaders = []): array
{
    return [
        'status'  => $status,
        'headers' => array_merge(['Content-Type' => 'application/json'], $extraHeaders),
        'body'    => json_encode(['error' => $message], JSON_UNESCAPED_SLASHES),
    ];
}

/**
 * Core endpoint logic, extracted so it's testable without booting a real
 * HTTP request: no header()/http_response_code()/echo, just inputs in,
 * a {status, headers, body} triple out.
 *
 * @param array    $server       $_SERVER (or a fake for tests)
 * @param string   $body         raw request body ($_SERVER-style, from php://input)
 * @param callable $lookup       function(string[] $ips): array<string,array> — normally
 *                                fn(array $ips) => lookup_ips($ips), injectable so tests
 *                                can simulate a missing/corrupt database
 * @param ?callable $rateLimiter function(string $clientIp): array{limited:bool,retry_after:int},
 *                                defaults to default_lookup_rate_limiter(); injectable so
 *                                tests can force the 429 path without real APCu
 *
 * @return array{status:int, headers:array<string,string>, body:string}
 */
function handle_lookup_request(array $server, string $body, callable $lookup, ?callable $rateLimiter = null): array
{
    $rateLimiter ??= 'default_lookup_rate_limiter';

    if (($server['REQUEST_METHOD'] ?? 'POST') !== 'POST') {
        return lookup_endpoint_json_error(405, 'This endpoint accepts POST only.');
    }

    // Body-size cap. Checked before JSON parsing (cheap, and avoids decoding
    // an oversized payload just to reject it).
    if (strlen($body) > LOOKUP_MAX_BODY_BYTES) {
        error_log(sprintf(
            'ip2geo api/lookup.php: request body too large (%d bytes, max %d)',
            strlen($body),
            LOOKUP_MAX_BODY_BYTES
        ));
        return lookup_endpoint_json_error(413, 'Request body too large (max 2 MB).');
    }

    $data = json_decode($body, true);
    if (!is_array($data) || !isset($data['ips']) || !is_array($data['ips'])) {
        return lookup_endpoint_json_error(400, 'Expected JSON body {"ips": [...]}.');
    }

    // Dedupe, preserving first-seen order, before the cap check (the cap is
    // on *unique* IPs, per the design doc).
    $rawIps = [];
    foreach ($data['ips'] as $raw) {
        $ip = trim((string)$raw);
        if ($ip === '') {
            continue;
        }
        $rawIps[$ip] = true;
    }
    $rawIps = array_keys($rawIps);

    if (count($rawIps) > LOOKUP_MAX_UNIQUE_IPS) {
        error_log(sprintf(
            'ip2geo api/lookup.php: too many unique IPs (%d, max %d)',
            count($rawIps),
            LOOKUP_MAX_UNIQUE_IPS
        ));
        return lookup_endpoint_json_error(413, 'Too many IPs (max 10,000 unique).');
    }

    $clientIp = lookup_endpoint_client_ip($server);
    $rate     = $rateLimiter($clientIp);
    if (!empty($rate['limited'])) {
        $retryAfter = (int)($rate['retry_after'] ?? LOOKUP_RATE_LIMIT_WINDOW_SECONDS);
        return lookup_endpoint_json_error(
            429,
            "Too many lookups from your network. Try again in {$retryAfter}s.",
            ['Retry-After' => (string)$retryAfter]
        );
    }

    $validIps   = [];
    $unresolved = [];
    foreach ($rawIps as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            $validIps[] = $ip;
        } else {
            $unresolved[] = $ip;
        }
    }

    try {
        $geo = $validIps === [] ? [] : $lookup($validIps);
    } catch (GeoDbUnavailableException $e) {
        error_log(sprintf(
            'ip2geo api/lookup.php: GeoIP database unavailable for %d IPs',
            count($validIps)
        ));
        return lookup_endpoint_json_error(503, 'Lookup data is updating. Try again in a minute.');
    }

    $results = [];
    foreach ($validIps as $ip) {
        $fields  = $geo[$ip] ?? [
            'country_iso_code'          => null,
            'country_name'              => null,
            'subdivision_1_name'        => null,
            'city_name'                 => null,
            'autonomous_system_number'  => null,
            'autonomous_system_org'     => null,
        ];
        $asnNum  = (string)($fields['autonomous_system_number'] ?? '');
        $asnOrg  = (string)($fields['autonomous_system_org'] ?? '');
        $ip4Uint = lookup_endpoint_ip4_to_uint($ip);

        $results[] = array_merge(['ip' => $ip], $fields, [
            'category' => classify_asn($asnNum, $asnOrg),
            'drop'     => $ip4Uint !== null && ip_in_spamhaus_drop($ip4Uint),
        ]);
    }

    return [
        'status'  => 200,
        'headers' => ['Content-Type' => 'application/json'],
        'body'    => json_encode(['results' => $results, 'unresolved' => $unresolved], JSON_UNESCAPED_SLASHES),
    ];
}

// ── HTTP wiring ──────────────────────────────────────────────────────────────
// Only runs when this file is the directly-requested script (real HTTP
// traffic). When required by PHPUnit, SCRIPT_FILENAME points at the test
// runner, not this file, so this block is skipped and only the functions
// above are defined — that's the seam the tests use.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    require_once __DIR__ . '/../config.php';

    $result = handle_lookup_request(
        $_SERVER,
        file_get_contents('php://input') ?: '',
        static fn(array $ips): array => lookup_ips($ips)
    );

    http_response_code($result['status']);
    foreach ($result['headers'] as $name => $value) {
        header($name . ': ' . $value);
    }
    echo $result['body'];
}
