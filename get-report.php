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

// ── Upgrade path (free report → paid) ────────────────────────────────────────
// NOTE: explicit parens required — ?? has lower precedence than ===
if (($_POST['action'] ?? '') === 'upgrade' && isset($_POST['upgrade_token'])) {
    $free_token = preg_replace('/[^a-f0-9\-]/', '', trim($_POST['upgrade_token']));
    if ($free_token === '') {
        header('Location: /?error=no_data'); exit;
    }

    // Rate-limit upgrade attempts per free token (10/hour) to prevent pending-row
    // and Stripe session spam. Keyed on the free token, not IP, so it survives proxies.
    if (function_exists('apcu_inc')) {
        $upg_key   = 'upg_rate:' . $free_token;
        $upg_count = apcu_inc($upg_key, 1, $upg_success);
        if (!$upg_success) {
            if (!apcu_add($upg_key, 1, 3600)) {
                $upg_count = apcu_inc($upg_key) ?: 1;
            } else {
                $upg_count = 1;
            }
        }
        if ($upg_count > 10) {
            header('Location: /?error=rate_limit'); exit;
        }
    }

    $con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
    if (mysqli_connect_errno()) {
        error_log('ip2geo get-report.php upgrade: DB connect failed: ' . mysqli_connect_error());
        header('Location: /?error=db'); exit;
    }

    $stmt = $con->prepare(
        'SELECT ip_list_json, geo_results_json FROM reports
         WHERE token = ? AND status = "free" AND report_expires_at > NOW()'
    );
    $stmt->bind_param('s', $free_token);
    $stmt->execute();
    $free_row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$free_row) {
        mysqli_close($con);
        header('Location: /?error=no_data'); exit;
    }

    $raw_json        = $free_row['ip_list_json'];
    $geo_results_raw = $free_row['geo_results_json'];
    $submission_hash = hash('sha256', $raw_json);

    // Check if a paid report for this IP list already exists
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
        mysqli_close($con);
        header('Location: /report.php?token=' . urlencode($cached['token'])); exit;
    }

    // Generate new paid token
    // TODO (low priority): UUID4 generation and Stripe session creation are
    // duplicated three times in this file. Extract generate_token() and
    // create_stripe_session() helpers when next touching this file.
    $rand  = bin2hex(random_bytes(16));
    $token = implode('-', [
        substr($rand, 0, 8),
        substr($rand, 8, 4),
        '4' . substr($rand, 13, 3),
        dechex(hexdec(substr($rand, 16, 2)) & 0x3f | 0x80) . substr($rand, 18, 2),
        substr($rand, 20, 12),
    ]);

    $stmt = $con->prepare(
        'INSERT INTO reports
           (token, submission_hash, ip_list_json, geo_results_json, status, pending_expires_at, created_at)
         VALUES (?, ?, ?, ?, "pending", DATE_ADD(NOW(), INTERVAL 1 HOUR), NOW())'
    );
    $stmt->bind_param('ssss', $token, $submission_hash, $raw_json, $geo_results_raw);
    if (!$stmt->execute()) {
        error_log('ip2geo get-report.php upgrade INSERT failed: ' . $stmt->error);
        $stmt->close();
        mysqli_close($con);
        header('Location: /?error=db'); exit;
    }
    $stmt->close();
    mysqli_close($con);

    \Stripe\Stripe::setApiKey($stripe_secret_key);
    $base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
              . '://' . $host;
    try {
        $session = \Stripe\Checkout\Session::create([
            'payment_method_types' => ['card'],
            'line_items'           => [[
                'price_data' => [
                    'currency'     => 'usd',
                    'unit_amount'  => 900,
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
            'cancel_url'           => $base_url . '/report.php?token=' . urlencode($free_token),
        ]);
    } catch (\Stripe\Exception\ApiErrorException $e) {
        error_log('ip2geo Stripe session create failed (upgrade): ' . $e->getMessage());
        header('Location: /report.php?token=' . urlencode($free_token) . '&error=payment'); exit;
    }

    // Phase 3: fire checkout_started server-side before Stripe redirect.
    // Analytical only — swallow any failure so the redirect always proceeds.
    try {
        $ev_con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
        if ($ev_con) {
            $ev_sid_raw = $_COOKIE['report_sid_' . $free_token] ?? null;
            $ev_sid = ($ev_sid_raw !== null && preg_match('/^[0-9a-f]{32}$/', $ev_sid_raw)) ? $ev_sid_raw : null;
            $ev_ins = $ev_con->prepare(
                'INSERT INTO report_events (token, event_type, session_id) VALUES (?, "checkout_started", ?)'
            );
            $ev_ins->bind_param('ss', $free_token, $ev_sid);
            $ev_ins->execute();
            $ev_ins->close();
            mysqli_close($ev_con);
        }
    } catch (\Throwable $e) {
        error_log('ip2geo get-report.php checkout_started INSERT failed: ' . $e->getMessage());
    }

    header('Location: ' . $session->url);
    exit;
}

// ── Determine request tier ────────────────────────────────────────────────────
$tier = $_POST['tier'] ?? 'paid';
if (!in_array($tier, ['free', 'paid'], true)) {
    $tier = 'paid';
}

// ── Rate limiting (free tier only, pre-DB) ────────────────────────────────────
// Increment first, then check — avoids race where two concurrent requests both
// read count=9, both pass, both increment to 10+.
// apcu_add is atomic (set-if-not-exists); avoids the race where two concurrent
// "first" requests both see !$success and both reset the counter to 1.
if ($tier === 'free' && function_exists('apcu_inc')) {
    $rate_key  = 'free_rate:' . md5($_SERVER['REMOTE_ADDR'] ?? '');
    $new_count = apcu_inc($rate_key, 1, $success);
    if (!$success) {
        // Key didn't exist yet — use apcu_add for atomic set-if-not-exists
        if (!apcu_add($rate_key, 1, 3600)) {
            // Lost the race: another request just created it, increment theirs
            $new_count = apcu_inc($rate_key) ?: 1;
        } else {
            $new_count = 1;
        }
    }
    if ($new_count > 10) {
        header('Location: /?error=rate_limit'); exit;
    }
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

// ── Free report path ─────────────────────────────────────────────────────────
if ($tier === 'free') {
    // Dedup: if a valid free report already exists for this IP list, reuse it.
    // Prevents duplicate rows when the user clicks the CTA more than once.
    $dedup = $con->prepare(
        'SELECT token FROM reports
         WHERE submission_hash = ? AND status = "free" AND report_expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1'
    );
    $dedup->bind_param('s', $submission_hash);
    $dedup->execute();
    $existing = $dedup->get_result()->fetch_assoc();
    $dedup->close();
    if ($existing) {
        mysqli_close($con);
        header('Location: /report.php?token=' . urlencode($existing['token'])); exit;
    }

    // Generate free report token (same UUID4 format as paid)
    $rand  = bin2hex(random_bytes(16));
    $token = implode('-', [
        substr($rand, 0, 8),
        substr($rand, 8, 4),
        '4' . substr($rand, 13, 3),
        dechex(hexdec(substr($rand, 16, 2)) & 0x3f | 0x80) . substr($rand, 18, 2),
        substr($rand, 20, 12),
    ]);

    // Phase 4: acquisition_source — capture referrer at submission time
    $acquisition_source = null;
    $raw_acq = $_POST['acquisition_source'] ?? '';
    if ($raw_acq !== '') {
        $acquisition_source = substr(trim($raw_acq), 0, 2000);
    }

    $stmt = $con->prepare(
        'INSERT INTO reports
           (token, submission_hash, ip_list_json, geo_results_json,
            status, pending_expires_at, report_expires_at, acquisition_source, created_at)
         VALUES (?, ?, ?, ?, "free",
                 DATE_ADD(NOW(), INTERVAL 7 DAY),
                 DATE_ADD(NOW(), INTERVAL 7 DAY), ?, NOW())'
    );
    $stmt->bind_param('sssss', $token, $submission_hash, $raw_json, $geo_results_raw, $acquisition_source);
    if (!$stmt->execute()) {
        error_log('ip2geo get-report.php free INSERT failed: ' . $stmt->error);
        $stmt->close();
        mysqli_close($con);
        header('Location: /?error=db'); exit;
    }
    $stmt->close();
    mysqli_close($con);
    header('Location: /report.php?token=' . urlencode($token)); exit;
}

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
          . '://' . $host;

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
