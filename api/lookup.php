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
require_once __DIR__ . '/../includes/client-ip.php';  // lookup_endpoint_client_ip()
require_once __DIR__ . '/../includes/rate-limit.php'; // default_lookup_rate_limiter(), cost budget per IP

// Cap on unique IPs per request and on raw body size.
if (!defined('LOOKUP_MAX_UNIQUE_IPS')) {
    define('LOOKUP_MAX_UNIQUE_IPS', 10000);
}
if (!defined('LOOKUP_MAX_BODY_BYTES')) {
    define('LOOKUP_MAX_BODY_BYTES', 2 * 1024 * 1024); // 2 MB
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
 * @param ?callable $rateLimiter function(string $clientIp, int $cost): array{limited:bool,retry_after:int},
 *                                defaults to default_lookup_rate_limiter() on the API bucket;
 *                                $cost is lookup_rate_cost() of the unique IP count.
 *                                Injectable so tests can force the 429 path without real APCu
 *
 * @return array{status:int, headers:array<string,string>, body:string}
 */
function handle_lookup_request(array $server, string $body, callable $lookup, ?callable $rateLimiter = null): array
{
    $rateLimiter ??= static fn(string $ip, int $cost): array => default_lookup_rate_limiter($ip, LOOKUP_RATE_BUCKET_API, $cost);

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
    $rate     = $rateLimiter($clientIp, lookup_rate_cost(count($rawIps)));
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
