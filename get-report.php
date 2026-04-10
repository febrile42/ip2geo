<?php
/**
 * Token creation + Stripe Checkout redirect.
 *
 * Called when the user clicks "Get Full Report + Block Script — $9".
 * Stores ip_list_json at this point so report.php can generate the report
 * after payment without relying on POST data or server sessions.
 *
 * Expected: POST with ip_classified_json (JSON array of classified IPs).
 * Falls back to a redirect back to the homepage on any error.
 */

require __DIR__ . '/config.php';
require __DIR__ . '/asn_classification.php';
require __DIR__ . '/vendor/autoload.php';

// ── Validate input ────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /');
    exit;
}

$allowed_hosts = ['ip2geo.org', 'staging.ip2geo.org'];
$host = strtolower(explode(':', $_SERVER['HTTP_HOST'] ?? '')[0]);
if (!in_array($host, $allowed_hosts, true)) {
    header('Location: /');
    exit;
}

// Extract IP + freq from client POST — classification fields are discarded and
// recomputed server-side. Never trust browser-submitted geo/ASN/classification data.
$raw_client_json = $_POST['ip_classified_json'] ?? '';
if ($raw_client_json === '') {
    header('Location: /?error=no_data');
    exit;
}
// Size guard: reject oversized payloads before hitting json_decode
if (strlen($raw_client_json) > 10 * 1024 * 1024) {
    header('Location: /?error=too_large');
    exit;
}

$client_ip_data = json_decode($raw_client_json, true);
if (!is_array($client_ip_data) || count($client_ip_data) === 0) {
    header('Location: /?error=no_data');
    exit;
}

// Validate IPs; preserve freq (low-risk user data: affects ranking only, not classification)
$ip_freq_map = [];
foreach ($client_ip_data as $entry) {
    $ip = filter_var($entry['ip'] ?? '', FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    if ($ip === false) continue;
    $freq = max(1, (int)($entry['freq'] ?? 1));
    $ip_freq_map[$ip] = $freq;
}
if (empty($ip_freq_map)) {
    header('Location: /?error=no_data');
    exit;
}

// ── Generate token ────────────────────────────────────────────────────────────

$rand  = bin2hex(random_bytes(16));
$token = implode('-', [
    substr($rand, 0, 8),
    substr($rand, 8, 4),
    '4' . substr($rand, 13, 3),
    dechex(hexdec(substr($rand, 16, 2)) & 0x3f | 0x80) . substr($rand, 18, 2),
    substr($rand, 20, 12),
]);

// ── Persist to DB ─────────────────────────────────────────────────────────────

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    error_log('ip2geo get-report.php DB connect failed: ' . mysqli_connect_error());
    header('Location: /?error=db');
    exit;
}

// ── Resolve classification: cache-first, re-classify as fallback ──────────────
// index.php writes a 30-min cache after each lookup. A hit avoids re-running all
// MaxMind queries. A miss (> 30 min elapsed, or attacker bypass attempt) falls back
// to full server-side re-classification. Security holds either way.

$sorted_ips = array_keys($ip_freq_map);
sort($sorted_ips);
$cache_key = hash('sha256', implode(',', $sorted_ips));

$cache_stmt = $con->prepare(
    'SELECT ip_list_json, geo_json FROM geo_classification_cache
     WHERE cache_key = ? AND expires_at > NOW()'
);
$cache_stmt->bind_param('s', $cache_key);
$cache_stmt->execute();
$cache_row = $cache_stmt->get_result()->fetch_assoc();
$cache_stmt->close();

if ($cache_row) {
    $raw_json        = $cache_row['ip_list_json'];
    $geo_results_raw = $cache_row['geo_json'];
} else {
    // Cache miss: re-classify server-side (authoritative, no browser trust)
    $ip_classified_data = [];
    $geo_results_data   = [];

    foreach ($ip_freq_map as $ip => $freq) {
        $ip_int = sprintf('%u', ip2long($ip));
        $query  = 'SELECT loc.country_iso_code, loc.country_name, loc.subdivision_1_name, loc.city_name,
            asn_net.autonomous_system_number, asn_net.autonomous_system_org
        FROM (
            SELECT geoname_id, network_end_integer
            FROM geoip2_network_current_int
            WHERE ' . $ip_int . ' >= network_start_integer
            ORDER BY network_start_integer DESC LIMIT 1
        ) city_net
        LEFT JOIN geoip2_location_current loc
            ON (city_net.geoname_id = loc.geoname_id AND loc.locale_code = \'en\')
        LEFT JOIN (
            SELECT autonomous_system_number, autonomous_system_org
            FROM geoip2_asn_current_int
            WHERE ' . $ip_int . ' >= network_start_integer
            ORDER BY network_start_integer DESC LIMIT 1
        ) asn_net ON 1=1
        WHERE ' . $ip_int . ' <= city_net.network_end_integer';

        $result  = mysqli_query($con, $query);
        $row     = $result ? mysqli_fetch_assoc($result) : null;

        $asn_num  = $row['autonomous_system_number'] ?? '';
        $asn_org  = $row['autonomous_system_org'] ?? '';
        $category = classify_asn((string)$asn_num, (string)$asn_org);
        $country  = $row['country_iso_code'] ?? '';

        $ip_classified_data[] = [
            'ip'             => $ip,
            'asn'            => $asn_num !== '' ? 'AS' . $asn_num : '',
            'asn_org'        => $asn_org,
            'classification' => $category,
            'country'        => $country,
            'freq'           => $freq,
        ];
        $geo_results_data[] = [
            'ip'             => $ip,
            'country'        => $country,
            'country_name'   => $row['country_name'] ?? '',
            'region'         => $row['subdivision_1_name'] ?? '',
            'city'           => $row['city_name'] ?? '',
            'asn'            => $asn_num !== '' ? 'AS' . $asn_num : '',
            'asn_org'        => $asn_org,
            'classification' => $category,
            'freq'           => $freq,
        ];
    }

    $raw_json        = json_encode($ip_classified_data);
    $geo_results_raw = json_encode($geo_results_data);
}

$submission_hash = hash('sha256', $raw_json);

// Check for a cached paid/redeemed report for the same IP list
$stmt = $con->prepare(
    'SELECT token, status FROM reports
     WHERE submission_hash = ? AND status IN ("paid","redeemed")
       AND (report_expires_at IS NULL OR report_expires_at > NOW())
     ORDER BY created_at DESC LIMIT 1'
);
$stmt->bind_param('s', $submission_hash);
$stmt->execute();
$cached = $stmt->get_result()->fetch_assoc();
$stmt->close();

if ($cached) {
    // Same IP list already paid — serve the cached report directly
    mysqli_close($con);
    header('Location: /report.php?token=' . urlencode($cached['token']));
    exit;
}

$stmt = $con->prepare(
    'INSERT INTO reports
       (token, submission_hash, ip_list_json, geo_results_json, status, pending_expires_at, created_at)
     VALUES (?, ?, ?, ?, "pending", DATE_ADD(NOW(), INTERVAL 1 HOUR), NOW())'
);
$stmt->bind_param('ssss', $token, $submission_hash, $raw_json, $geo_results_raw);
if (!$stmt->execute()) {
    error_log('ip2geo get-report.php INSERT failed: ' . $stmt->error);
    $stmt->close();
    mysqli_close($con);
    header('Location: /?error=db');
    exit;
}
$stmt->close();
mysqli_close($con);

// ── Create Stripe Checkout session ───────────────────────────────────────────

\Stripe\Stripe::setApiKey($stripe_secret_key);

$base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
          . '://' . $_SERVER['HTTP_HOST'];

try {
    $session = \Stripe\Checkout\Session::create([
        'payment_method_types' => ['card'],
        'line_items'           => [[
            'price_data' => [
                'currency'     => 'usd',
                'unit_amount'  => 900,  // $9.00 in cents
                'product_data' => [
                    'name'        => 'ip2geo Threat Report + Block Script',
                    'description' => 'Rule-based threat summary, AbuseIPDB reputation data, and ready-to-run firewall block script for your IP list.',
                ],
            ],
            'quantity' => 1,
        ]],
        'mode'                 => 'payment',
        'client_reference_id'  => $token,
        'success_url'          => $base_url . '/report.php?token=' . urlencode($token) . '&session_id={CHECKOUT_SESSION_ID}',
        'cancel_url'           => $base_url . '/?cancelled=1',
    ]);
} catch (\Stripe\Exception\ApiErrorException $e) {
    error_log('ip2geo Stripe session create failed: ' . $e->getMessage());
    header('Location: /?error=payment');
    exit;
}

header('Location: ' . $session->url);
exit;
