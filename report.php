<?php
/**
 * Paid threat report page.
 *
 * Token lifecycle:
 *   pending  → validate → mark paid → generate + store report_json → mark redeemed
 *   paid     → (webhook beat redirect) → same generation path
 *   redeemed → serve cached report_json (no regeneration)
 *
 * If token is invalid, expired, or not found: show error page.
 */

require __DIR__ . '/config.php';
require __DIR__ . '/asn_classification.php';
require __DIR__ . '/report_functions.php';
require __DIR__ . '/email_helper.php';
require __DIR__ . '/vendor/autoload.php';

define('DEMO_TOKEN', '00000000-0000-0000-0000-000000000000');

// ── Token validation ──────────────────────────────────────────────────────────

$token = isset($_GET['token']) ? trim($_GET['token']) : '';

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    error_log('ip2geo report.php DB connect failed: ' . mysqli_connect_error());
    render_error('Database unavailable. Please try again shortly.');
    exit;
}

$stmt = $con->prepare(
    'SELECT token, submission_hash, ip_list_json, geo_results_json, status,
            pending_expires_at, report_expires_at, report_json,
            notification_email, email_sent_at, stripe_payment_intent,
            data_consent
     FROM reports WHERE token = ?'
);
$stmt->bind_param('s', $token);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$row) {
    mysqli_close($con);
    render_error('This report link is invalid or has expired. If you paid and cannot access your report, contact us at support@ip2geo.org.');
    exit;
}

$status             = $row['status'];
$notification_email = $row['notification_email'] ?? '';  // may be overwritten below from Stripe session

if ($status === 'pending') {
    if (strtotime($row['pending_expires_at']) < time()) {
        mysqli_close($con);
        render_error('This report link has expired (payment window was 1 hour). If you completed payment, contact us at support@ip2geo.org with your payment confirmation and we will restore your report.');
        exit;
    }

    // Primary success path: Stripe appends ?session_id= to the success_url.
    // Retrieve the session and verify payment_status before generating the report.
    $stripe_session_id = isset($_GET['session_id']) ? trim($_GET['session_id']) : '';
    if ($stripe_session_id === '') {
        // No session_id — user navigated directly before webhook fired
        mysqli_close($con);
        render_error('Your payment is being processed. Please wait a moment and reload this page. If this message persists, contact support@ip2geo.org.');
        exit;
    }

    \Stripe\Stripe::setApiKey($stripe_secret_key);
    try {
        $stripe_session = \Stripe\Checkout\Session::retrieve($stripe_session_id);
    } catch (\Stripe\Exception\ApiErrorException $e) {
        error_log('ip2geo report.php Stripe retrieve failed: ' . $e->getMessage());
        mysqli_close($con);
        send_alert_email(
            'Stripe session retrieve failed — payment may be undelivered',
            build_payment_alert_html('Stripe session retrieve failed on success_url. Customer may have paid but cannot access their report.', [
                'token'      => $token,
                'session_id' => $stripe_session_id,
                'error'      => $e->getMessage(),
                'note'       => 'Payment status unknown. Retrieve the checkout session in Stripe to confirm if payment completed.',
            ]),
            $resend_api_key ?? '', $resend_from ?? ''
        );
        render_error('Payment verification failed. Please contact support@ip2geo.org with your token: ' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8'));
        exit;
    }

    // Guard: session_id must belong to this token
    if (($stripe_session->client_reference_id ?? '') !== $token) {
        error_log('ip2geo report.php: session_id/token mismatch for token ' . $token);
        mysqli_close($con);
        send_alert_email(
            'Session/token mismatch — possible fraud or bug',
            build_payment_alert_html('Stripe session client_reference_id does not match the URL token. Could indicate a tampered URL or an internal bug.', [
                'token'          => $token,
                'session_id'     => $stripe_session_id,
                'payment_intent' => $stripe_session->payment_intent ?? '',
                'email'          => trim($stripe_session->customer_details->email ?? ''),
                'note'           => 'Token in URL: ' . $token . ' | Token in Stripe session: ' . ($stripe_session->client_reference_id ?? '(none)'),
            ]),
            $resend_api_key ?? '', $resend_from ?? ''
        );
        render_error('Payment verification failed. Please contact support@ip2geo.org with your token: ' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8'));
        exit;
    }

    if ($stripe_session->payment_status !== 'paid') {
        mysqli_close($con);
        render_error('Your payment is being processed. Please wait a moment and reload this page. If this message persists, contact support@ip2geo.org.');
        exit;
    }

    // Payment confirmed via Stripe — fall through to report generation.
    // The UPDATE below uses status IN ("pending","paid") so this works without
    // a separate mark-paid step. The webhook may still fire and no-op.
    $notification_email = trim($stripe_session->customer_details->email ?? '');
}

if ($status === 'free') {
    if ($row['report_expires_at'] && strtotime($row['report_expires_at']) < time()) {
        mysqli_close($con);
        render_error('This free report expired after 7 days. Submit your logs again — it takes under 10 seconds.', true);
        exit;
    }

    // Lazy generation: generate report_json on first visit (no AbuseIPDB for free tier)
    if ($row['report_json'] === null) {
        $mutex_key = 'gen_lock_free:' . preg_replace('/[^a-f0-9\-]/', '', $token);
        $got_lock  = !function_exists('apcu_add') || apcu_add($mutex_key, 1, 30);

        if ($got_lock) {
            $ip_data_free = json_decode($row['ip_list_json'], true) ?? [];
            $total_free   = count($ip_data_free);
            $cat_counts_free = ['scanning' => 0, 'cloud' => 0, 'vpn' => 0, 'residential' => 0, 'unknown' => 0];
            $country_counts_free = [];
            foreach ($ip_data_free as $e) {
                $cat = $e['classification'] ?? 'unknown';
                $cat_counts_free[$cat] = ($cat_counts_free[$cat] ?? 0) + 1;
                $cc = $e['country'] ?? '';
                if ($cc !== '') $country_counts_free[$cc] = ($country_counts_free[$cc] ?? 0) + 1;
            }
            $scanning_proxy_free = $cat_counts_free['scanning'] + $cat_counts_free['vpn'];
            $verdict_free        = compute_verdict($scanning_proxy_free, $total_free, $cat_counts_free['cloud']);
            $top25_free          = rank_ips($ip_data_free, 25);

            arsort($country_counts_free);
            $top_countries_free = array_slice($country_counts_free, 0, 5, true);

            $free_report = [
                'verdict'        => $verdict_free,
                'total_ips'      => $total_free,
                'scanning_pct'   => $total_free > 0 ? round(($scanning_proxy_free / $total_free) * 100) : 0,
                'scanning_count' => $scanning_proxy_free,
                'cat_counts'     => $cat_counts_free,
                'top_countries'  => $top_countries_free,
                'top25'          => $top25_free,
                'block_ips'      => [],
                'asn_ranges'     => [],
                'generated_at'   => date('Y-m-d H:i:s'),
                'abuseipdb_note' => null,
            ];
            $free_report_json = json_encode($free_report);

            $stmt_upd = $con->prepare(
                'UPDATE reports SET report_json = ? WHERE token = ? AND status = "free" AND report_json IS NULL'
            );
            $stmt_upd->bind_param('ss', $free_report_json, $token);
            $stmt_upd->execute();
            $stmt_upd->close();

            if (function_exists('apcu_delete')) {
                apcu_delete($mutex_key);
            }

            $row['report_json'] = $free_report_json;
        } else {
            // Another request is generating — brief wait then reload
            mysqli_close($con);
            header('Refresh: 1; url=/report.php?token=' . urlencode($token));
            echo '<!DOCTYPE html><html><head><meta http-equiv="refresh" content="1"></head><body>Generating report...</body></html>';
            exit;
        }
    }

    // Increment anonymous view counter
    $stmt_vc = $con->prepare('UPDATE reports SET view_count = view_count + 1 WHERE token = ?');
    $stmt_vc->bind_param('s', $token);
    $stmt_vc->execute();
    $stmt_vc->close();

    $report           = json_decode($row['report_json'], true);
    $all_ips_free     = json_decode($row['ip_list_json'], true) ?? [];
    $expires_at_free  = $row['report_expires_at'];
    mysqli_close($con);
    render_free_report($report, $token, $expires_at_free, $all_ips_free);
    exit;
}

if ($status === 'redeemed') {
    // Check expiry (NULL = permanent paid report)
    if ($row['report_expires_at'] && strtotime($row['report_expires_at']) < time()) {
        mysqli_close($con);
        render_error('This report link has expired. Your data is no longer stored. Submit your logs again at ip2geo.org for a fresh analysis.');
        exit;
    }
    // Serve cached report
    $report = json_decode($row['report_json'], true);
    $ip_data_for_render = json_decode($row['ip_list_json'], true) ?? [];
    $cached_email      = $row['notification_email'] ?? '';
    $cached_email_sent = $row['email_sent_at'] !== null;
    $data_consent      = $row['data_consent'] === null ? null : (int)$row['data_consent'];
    $community_data    = [];
    if ($data_consent === 1 && !empty($report['top25'])) {
        if ($token === DEMO_TOKEN) {
            // Hardcoded sample data for demo report — no DB query, rolling 7-day counts.
            $_samples = [
                '185.220.101.1'  => 31, '185.220.101.2'  => 29,
                '185.220.101.3'  => 27, '185.220.101.4'  => 24,
                '185.220.101.5'  => 22, '185.220.101.6'  => 19,
                '185.220.101.7'  => 17, '185.220.101.8'  => 14,
                '185.220.101.9'  => 11, '185.220.101.10' => 8,
                '185.220.101.11' => 7,  '185.220.101.12' => 5,
                '185.220.101.13' => 4,  '185.220.101.14' => 3,
                '5.39.50.1'      => 12, '5.39.50.2'      => 8,
                '45.141.215.1'   => 6,  '185.220.100.240'=> 5,
                '185.220.100.241'=> 3,
            ];
            $_ip_stats    = [];
            $_first_seen  = [];
            foreach ($_samples as $_ip => $_count) {
                $_ip_stats[$_ip]   = $_count;
                $_first_seen[$_ip] = gmdate('Y-m-d', strtotime('-' . (60 - (int)substr($_ip, -1) * 2) . ' days'));
            }
            $community_data = ['ip_stats' => $_ip_stats, 'first_seen' => $_first_seen];
        } else {
            $community_data = fetch_community_data($con, array_column($report['top25'], 'ip'));
        }
    }
    mysqli_close($con);
    maybe_serve_script_download($report, $token);
    render_report($report, $token, $row['report_expires_at'], $ip_data_for_render, $cached_email, $cached_email_sent, $data_consent, $community_data);
    exit;
}

// status === 'paid' (webhook confirmed but report not yet generated, or
// user arrived via success_url before webhook fired and we just marked paid above)
// Generate the report now.

// Mark as paid if arriving via success_url and status is still pending
// (primary flow: success_url fires before webhook)
if ($status === 'paid') {
    // Already marked paid (by webhook or prior visit) — fall through to generation
}

// ── Report generation ─────────────────────────────────────────────────────────

$ip_data = json_decode($row['ip_list_json'], true);
if (!is_array($ip_data)) {
    error_log('ip2geo report.php: ip_list_json decode failed for token ' . $token);
    mysqli_close($con);
    send_alert_email(
        'Report generation failed after confirmed payment',
        build_payment_alert_html('ip_list_json could not be decoded. Payment was confirmed but report cannot be generated. Customer needs a refund or manual fix.', [
            'token'          => $token,
            'payment_intent' => $row['stripe_payment_intent'] ?? '',
            'email'          => $notification_email,
            'note'           => 'ip_list_json in DB is null or malformed. Check the reports row.',
        ]),
        $resend_api_key ?? '', $resend_from ?? ''
    );
    render_error('Report generation failed. Please contact support@ip2geo.org with your token: ' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8'));
    exit;
}

// Aggregate: count by classification and country
$total         = count($ip_data);
$cat_counts    = ['scanning' => 0, 'cloud' => 0, 'vpn' => 0, 'residential' => 0, 'unknown' => 0];
$country_counts = [];
foreach ($ip_data as $entry) {
    $cat = $entry['classification'] ?? 'unknown';
    $cat_counts[$cat] = ($cat_counts[$cat] ?? 0) + 1;
    $cc = $entry['country'] ?? '';
    if ($cc !== '') $country_counts[$cc] = ($country_counts[$cc] ?? 0) + 1;
}

$scanning_proxy = $cat_counts['scanning'] + $cat_counts['vpn'];
$scanning_pct   = $total > 0 ? $scanning_proxy / $total : 0;

$verdict = compute_verdict($scanning_proxy, $total, $cat_counts['cloud']);
$top25   = rank_ips($ip_data, 25);

// All scanning/VPN IPs for block scripts — freq-ordered (used by maybe_serve_script_download)
$block_ips_entries = array_values(array_filter($ip_data, fn($e) => in_array($e['classification'] ?? '', ['scanning', 'vpn'], true)));
usort($block_ips_entries, fn($a, $b) => ($b['freq'] ?? 1) <=> ($a['freq'] ?? 1));
$block_ips = array_column($block_ips_entries, 'ip');

// ── Concurrency guard ─────────────────────────────────────────────────────────
// The Stripe success_url redirect and webhook can arrive simultaneously, causing
// two requests to reach this generation path for the same token. GET_LOCK()
// serialises them: the second request waits, then re-reads status='redeemed'
// and serves the cached report instead of calling AbuseIPDB again.
$gen_lock = 'ip2geo_gen_' . preg_replace('/[^a-f0-9-]/', '', $token);
$lock_row = $con->query('SELECT GET_LOCK("' . $gen_lock . '", 30)')->fetch_row();
if (!$lock_row || !$lock_row[0]) {
    // Another process held the lock for 30 s without releasing — give up.
    mysqli_close($con);
    render_error('Your report is being prepared. Please refresh this page in a moment.');
    exit;
}

// Re-read status after acquiring the lock: a concurrent request may have
// already finished generation while we were waiting.
$recheck_stmt = $con->prepare(
    'SELECT status, report_json, report_expires_at, notification_email, email_sent_at
     FROM reports WHERE token = ?'
);
$recheck_stmt->bind_param('s', $token);
$recheck_stmt->execute();
$recheck = $recheck_stmt->get_result()->fetch_assoc();
$recheck_stmt->close();
if ($recheck && $recheck['status'] === 'redeemed' && $recheck['report_json']) {
    $con->query('SELECT RELEASE_LOCK("' . $gen_lock . '")');
    $report             = json_decode($recheck['report_json'], true);
    $cached_email       = $recheck['notification_email'] ?? '';
    $cached_email_sent  = $recheck['email_sent_at'] !== null;
    $data_consent_gen   = null;
    mysqli_close($con);
    maybe_serve_script_download($report, $token);
    render_report($report, $token, $recheck['report_expires_at'], $ip_data, $cached_email, $cached_email_sent, $data_consent_gen, []);
    exit;
}

// AbuseIPDB enrichment
$top25   = enrich_abuseipdb($top25, $con, $abuseipdb_api_key ?? '');
$verdict = maybe_upgrade_verdict($verdict, $top25);

arsort($country_counts);
$top_countries = array_slice($country_counts, 0, 5, true);

// ASN ranges for scanning/VPN ASNs (DB must still be open here)
$asn_ranges = fetch_asn_ranges($con, $top25);

$report = [
    'verdict'         => $verdict,
    'total_ips'       => $total,
    'scanning_pct'    => round($scanning_pct * 100),
    'scanning_count'  => $scanning_proxy,
    'cat_counts'      => $cat_counts,
    'top_countries'   => $top_countries,
    'top25'           => $top25,
    'block_ips'       => $block_ips,
    'asn_ranges'      => $asn_ranges,
    'generated_at'    => date('Y-m-d H:i:s'),
    'abuseipdb_note'  => null,
];

// Store report + mark redeemed in one UPDATE (report_expires_at = NULL = permanent)
$report_json_str  = json_encode($report);
$report_expires   = null;
$stmt = $con->prepare(
    'UPDATE reports
     SET status = "redeemed", report_json = ?, report_expires_at = NULL, geo_results_json = NULL
     WHERE token = ? AND status IN ("pending","paid")'
);
$stmt->bind_param('ss', $report_json_str, $token);
$stmt->execute();
$stmt->close();
$is_new_redemption = true;

$email_was_sent = false;
if ($notification_email !== '' && !empty($resend_api_key) && !empty($resend_from)) {
    $email_was_sent = send_report_email($con, $token, $notification_email, $report_expires, $resend_api_key, $resend_from, $report['total_ips'] ?? 0);
}
$con->query('SELECT RELEASE_LOCK("' . $gen_lock . '")');
mysqli_close($con);

maybe_serve_script_download($report, $token);
render_report($report, $token, $report_expires, $ip_data, $notification_email, $email_was_sent, null, [], $is_new_redemption ?? false);
exit;

// ── AbuseIPDB enrichment ──────────────────────────────────────────────────────

function enrich_abuseipdb(array $ips, $con, string $api_key): array {
    if ($api_key === '') {
        foreach ($ips as &$entry) $entry['abuse_score'] = null;
        return $ips;
    }

    $today = date('Y-m-d');

    // Atomic quota check
    $con->begin_transaction();
    $usage_row = $con->query(
        'SELECT calls_made FROM abuseipdb_daily_usage WHERE usage_date = "' . $today . '" FOR UPDATE'
    )->fetch_assoc();
    $calls_so_far = $usage_row ? (int)$usage_row['calls_made'] : 0;

    // Separate cached vs uncached IPs
    $need_api = [];
    $ip_list_str = implode('","', array_map(fn($e) => $e['ip'], $ips));
    $cached_rows = [];
    if ($ip_list_str !== '') {
        $res = $con->query(
            'SELECT ip, confidence_score FROM abuseipdb_cache
             WHERE ip IN ("' . $ip_list_str . '")
               AND queried_at > DATE_SUB(NOW(), INTERVAL 7 DAY)'
        );
        while ($r = $res->fetch_assoc()) {
            $cached_rows[$r['ip']] = (int)$r['confidence_score'];
        }
    }

    foreach ($ips as $entry) {
        if (!isset($cached_rows[$entry['ip']])) {
            $need_api[] = $entry['ip'];
        }
    }

    $batch_size = count($need_api);
    if ($calls_so_far + $batch_size > 1000) {
        // Not enough quota — degrade gracefully
        $con->rollback();
        foreach ($ips as &$entry) {
            $entry['abuse_score'] = $cached_rows[$entry['ip']] ?? null;
        }
        // Signal to caller that AbuseIPDB was partially unavailable
        return $ips;
    }

    // Commit the quota reservation (increment after actual calls)
    $con->query(
        'INSERT INTO abuseipdb_daily_usage (usage_date, calls_made) VALUES ("' . $today . '", 0)
         ON DUPLICATE KEY UPDATE calls_made = calls_made'
    );
    $con->commit();

    // Parallel AbuseIPDB calls via curl_multi
    $actual_calls = 0;
    $api_results  = [];
    if (!empty($need_api)) {
        $multi   = curl_multi_init();
        $handles = [];
        foreach ($need_api as $ip) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => 'https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode($ip) . '&maxAgeInDays=90',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_HTTPHEADER     => ['Key: ' . $api_key, 'Accept: application/json'],
            ]);
            curl_multi_add_handle($multi, $ch);
            $handles[$ip] = $ch;
        }

        $running = null;
        do {
            curl_multi_exec($multi, $running);
            curl_multi_select($multi);
        } while ($running > 0);

        foreach ($handles as $ip => $ch) {
            $body = curl_multi_getcontent($ch);
            $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);
            if ($http === 200 && $body) {
                $data = json_decode($body, true);
                $score = (int)($data['data']['abuseConfidenceScore'] ?? 0);
                $total_reports = (int)($data['data']['totalReports'] ?? 0);
                $api_results[$ip] = ['score' => $score, 'total_reports' => $total_reports];
                $actual_calls++;
            }
        }
        curl_multi_close($multi);

        // Cache results + update actual quota used
        if ($actual_calls > 0) {
            foreach ($api_results as $ip => $result) {
                $stmt = $con->prepare(
                    'INSERT INTO abuseipdb_cache (ip, confidence_score, total_reports, queried_at)
                     VALUES (?, ?, ?, NOW())
                     ON DUPLICATE KEY UPDATE
                       confidence_score = VALUES(confidence_score),
                       total_reports    = VALUES(total_reports),
                       queried_at       = NOW()'
                );
                $stmt->bind_param('sii', $ip, $result['score'], $result['total_reports']);
                $stmt->execute();
                $stmt->close();
            }
            $con->query(
                'UPDATE abuseipdb_daily_usage
                 SET calls_made = calls_made + ' . $actual_calls . '
                 WHERE usage_date = "' . $today . '"'
            );
        }
    }

    // Attach scores to each IP entry
    foreach ($ips as &$entry) {
        $ip = $entry['ip'];
        if (isset($api_results[$ip])) {
            $entry['abuse_score']        = $api_results[$ip]['score'];
            $entry['abuse_total_reports'] = $api_results[$ip]['total_reports'];
        } elseif (isset($cached_rows[$ip])) {
            $entry['abuse_score'] = $cached_rows[$ip];
        } else {
            $entry['abuse_score'] = null;
        }
    }
    unset($entry);
    return $ips;
}

// ── Script download helper ────────────────────────────────────────────────────
// Called from both the redeemed (cached) and newly-generated paths so that
// ?format= requests work regardless of how the token was resolved.
// get_script_lines() lives in report_functions.php (testable pure function).

function maybe_serve_script_download(array $report, string $token): void {
    if (!isset($_GET['format'])) return;
    $fmt = $_GET['format'];

    $meta = [
        'sh-iptables'        => ['block-iptables.sh',        'text/x-sh'],
        'sh-ufw'             => ['block-ufw.sh',             'text/x-sh'],
        'sh-iptables-ranges' => ['block-iptables-ranges.sh', 'text/x-sh'],
        'sh-ufw-ranges'      => ['block-ufw-ranges.sh',      'text/x-sh'],
        'nginx-ips'          => ['block-nginx-ips.conf',     'text/plain'],
        'nginx-ranges'       => ['block-nginx-ranges.conf',  'text/plain'],
        'txt-ranges'         => ['cidr-ranges.txt',          'text/plain'],
    ];
    if (!isset($meta[$fmt])) return;

    $lines = get_script_lines($fmt, $report, $token);
    $body  = implode("\n", $lines) . "\n";
    [$filename, $content_type] = $meta[$fmt];

    header('Content-Type: ' . $content_type . '; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function include_block_rules_tabs(string $token, bool $has_ranges, array $report): void {
    $format_labels = [
        'sh-iptables-ranges' => 'block-iptables-ranges.sh',
        'sh-ufw-ranges'      => 'block-ufw-ranges.sh',
        'nginx-ranges'       => 'block-nginx-ranges.conf',
        'txt-ranges'         => 'cidr-ranges.txt',
        'sh-iptables'        => 'block-iptables.sh',
        'sh-ufw'             => 'block-ufw.sh',
        'nginx-ips'          => 'block-nginx-ips.conf',
    ];
    $render = function(string $fmt) use ($token, $report, $format_labels): void {
        $label   = $format_labels[$fmt];
        $content = htmlspecialchars(implode("\n", get_script_lines($fmt, $report, $token)), ENT_QUOTES, 'UTF-8');
        $href    = '/report.php?token=' . urlencode($token) . '&amp;format=' . urlencode($fmt);
        $fid     = 'fmt-' . $fmt;
        $label_e = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
        ?>
                    <div class="format-entry">
                        <button class="format-toggle button small" data-target="<?php echo $fid; ?>" data-label="<?php echo $label_e; ?>" aria-expanded="false">&#9656; <?php echo $label_e; ?></button>
                        <div id="<?php echo $fid; ?>" class="format-block" hidden>
                            <div class="format-actions">
                                <button class="copy-btn button small">&#128203; Copy</button>
                                <a href="<?php echo $href; ?>" class="button small">&#8595; Download</a>
                            </div>
                            <pre class="block-script-preview"><code><?php echo $content; ?></code></pre>
                        </div>
                    </div>
        <?php
    };
    ?>
            <div class="block-rules-tabs">
                <div class="block-rules-tablist" role="tablist" aria-label="Block by IP or by range">
                    <div class="block-rules-tab<?php echo $has_ranges ? ' active' : ''; ?>" id="tab-by-range" role="tab" tabindex="<?php echo $has_ranges ? '0' : '-1'; ?>" aria-selected="<?php echo $has_ranges ? 'true' : 'false'; ?>" aria-controls="panel-by-range"<?php echo $has_ranges ? '' : ' aria-disabled="true" title="No ASN ranges available for this report"'; ?>>Block by Range</div>
                    <div class="block-rules-tab<?php echo $has_ranges ? '' : ' active'; ?>" id="tab-by-ip" role="tab" tabindex="0" aria-selected="<?php echo $has_ranges ? 'false' : 'true'; ?>" aria-controls="panel-by-ip">Block by IP</div>
                </div>
                <div id="panel-by-range" class="block-rules-panel" role="tabpanel" aria-labelledby="tab-by-range"<?php echo $has_ranges ? '' : ' style="display:none"'; ?>>
                    <p class="cidr-explainer">Ranges cover all current and future IPs from this network &mdash; attackers rotate IPs, ranges don&rsquo;t.</p>
                    <?php if ($has_ranges):
                        foreach (['sh-iptables-ranges', 'sh-ufw-ranges', 'nginx-ranges', 'txt-ranges'] as $fmt) $render($fmt);
                    else: ?>
                    <p style="font-size:0.9em;opacity:0.5;margin:0.6em 0">No ASN ranges available for this report.</p>
                    <?php endif; ?>
                </div>
                <div id="panel-by-ip" class="block-rules-panel" role="tabpanel" aria-labelledby="tab-by-ip"<?php echo $has_ranges ? ' style="display:none"' : ''; ?>>
                    <?php foreach (['sh-iptables', 'sh-ufw', 'nginx-ips'] as $fmt) $render($fmt); ?>
                </div>
            </div>
<?php }

// ── Community context fetch ───────────────────────────────────────────────────

function fetch_community_data($con, array $ips): array {
    if (empty($ips)) return ['ip_stats' => [], 'first_seen' => []];

    $cutoff = gmdate('Y-m-d', strtotime('-7 days'));

    $placeholders = implode(',', array_fill(0, count($ips), '?'));
    $types        = str_repeat('s', count($ips));

    // Rolling 7-day report counts per IP
    $stmt = $con->prepare(
        "SELECT ip, SUM(report_count) AS report_count
         FROM community_ip_stats
         WHERE ip IN ({$placeholders})
           AND report_date >= ?
         GROUP BY ip"
    );
    $params = array_merge($ips, [$cutoff]);
    $stmt->bind_param($types . 's', ...$params);
    $stmt->execute();
    $ip_stats = [];
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) {
        $ip_stats[$r['ip']] = (int)$r['report_count'];
    }
    $stmt->close();

    // First-seen dates
    $stmt = $con->prepare(
        "SELECT ip, first_seen FROM community_ip_first_seen WHERE ip IN ({$placeholders})"
    );
    $stmt->bind_param($types, ...$ips);
    $stmt->execute();
    $first_seen = [];
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) {
        $first_seen[$r['ip']] = $r['first_seen'];
    }
    $stmt->close();

    return [
        'ip_stats'   => $ip_stats,
        'first_seen' => $first_seen,
    ];
}

function render_error(string $msg, bool $show_new_analysis_link = false): void {
    $title = 'Report Unavailable — ip2geo.org';
    render_page_open($title); ?>
    <section id="report" class="wrapper style4 fade-up">
        <div class="inner">
            <h2>Report Unavailable</h2>
            <p><?php echo htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php if ($show_new_analysis_link): ?>
            <p><a href="/" class="button small">Analyze new logs →</a></p>
            <?php else: ?>
            <p><a href="/" class="button small">← Back to ip2geo</a></p>
            <?php endif; ?>
        </div>
    </section>
    <?php render_page_close();
}

function render_report(array $report, string $token, ?string $expires_at, array $all_ips = [], string $notification_email = '', bool $email_sent = false, ?int $data_consent = null, array $community_data = [], bool $is_new_redemption = false): void {
    $verdict     = $report['verdict'];
    $verdict_lc  = strtolower($verdict);
    $total       = $report['total_ips'];
    $scan_pct    = $report['scanning_pct'];
    $scan_count  = $report['scanning_count'];
    $top25       = $report['top25'];
    $gen_date    = $report['generated_at'];
    $expires_fmt = $expires_at ? date('F j, Y', strtotime($expires_at)) : null;

    // Build chip data from all_ips
    // Only scanning + vpn appear in block scripts — count/show only those.
    $blockable_cats = ['scanning', 'vpn'];
    $all_cats   = ['scanning' => 0, 'cloud' => 0, 'vpn' => 0, 'residential' => 0, 'unknown' => 0];
    $all_ctries = [];
    foreach ($all_ips as $e) {
        $cat = $e['classification'] ?? 'unknown';
        $all_cats[$cat] = ($all_cats[$cat] ?? 0) + 1;
        if (in_array($cat, $blockable_cats)) {
            $cc = $e['country'] ?? '';
            if ($cc !== '') $all_ctries[$cc] = ($all_ctries[$cc] ?? 0) + 1;
        }
    }
    arsort($all_ctries);
    $blockable_count = ($all_cats['scanning'] ?? 0) + ($all_cats['vpn'] ?? 0);

    $verdict_text = [
        'HIGH'     => 'This traffic shows a high concentration of known scanning infrastructure. The ASN ranges below cover all current prefixes for these networks — blocking them will stop the majority of it.',
        'MODERATE' => 'This traffic is mixed — some scanning, some legitimate. Review the top sources below before blocking.',
        'LOW'      => 'No significant threat patterns detected. Most traffic appears to be from residential or commercial ISPs.',
    ][$verdict];

    $meta_desc = match($verdict) {
        'HIGH'     => "ip2geo threat report: HIGH risk — {$total} IPs analyzed, {$scan_pct}% from scanning infrastructure.",
        'MODERATE' => "ip2geo threat report: MODERATE risk — {$total} IPs analyzed, mixed threat sources.",
        default    => "ip2geo threat report: LOW risk — {$total} IPs analyzed, no significant threat patterns.",
    };

    $is_demo = ($token === DEMO_TOKEN);

    render_page_open('Threat Report — ip2geo.org', $meta_desc);
    // Embed full IP list for client-side filtering
    echo '<script>window.reportAllIps = ' . json_encode($all_ips) . ';</script>'; ?>
    <section id="report" class="wrapper style4 fade-up">
        <div class="inner">
            <?php if ($is_demo): ?>
            <div style="background:rgba(224,168,90,0.12);border-left:3px solid #e0a85a;padding:0.6em 1em;margin-bottom:1.5em;font-size:0.9em">
                <strong>Demo Report</strong> &mdash; These are real Tor exit nodes with real AbuseIPDB data.
                This is what a HIGH-threat report looks like.
                <a href="/" style="margin-left:1em">Run your own lookup &rarr;</a>
            </div>
            <?php elseif ($email_sent && $notification_email !== ''): ?>
            <?php $resend_link = '/send-report-link.php?token=' . urlencode($token); ?>
            <div class="report-email-notice sent">
                <span>&#10003; Report link sent to <strong><?php echo htmlspecialchars(mask_email($notification_email), ENT_QUOTES, 'UTF-8'); ?></strong>.
                <a href="<?php echo htmlspecialchars($resend_link, ENT_QUOTES, 'UTF-8'); ?>" style="margin-left:0.5em">Resend</a></span>
            </div>
            <?php endif; ?>

            <style>
                .report-header-row {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    gap: 1em;
                    margin-bottom: 0.5em;
                }
                .report-header-row h2 { margin: 0; }
                .report-header-stats { opacity: 0.6; font-size: 0.85em; margin: 0; white-space: nowrap; }
                .report-verdict-row { margin-top: 0.6em; }
                .report-verdict-row .asn-verdict { margin: 0; }
                @media (max-width: 736px) {
                    .report-header-row { flex-direction: column; align-items: flex-start; gap: 0.25em; }
                    .print-report-btn { display: none; }
                }
                .report-email-notice {
                    border-radius: 4px;
                    padding: 0.7em 1em;
                    margin-bottom: 1.5em;
                    font-size: 0.9em;
                    display: flex;
                    align-items: flex-start;
                    gap: 0.75em;
                    flex-wrap: wrap;
                }
                .report-email-notice.sent {
                    background: rgba(80,180,120,0.12);
                    border-left: 3px solid #50b478;
                }
                .report-email-notice.save {
                    background: rgba(224,168,90,0.12);
                    border-left: 3px solid #e0a85a;
                }
                .report-link-row {
                    display: flex;
                    align-items: center;
                    gap: 0.5em;
                    margin-top: 0.5em;
                    flex-wrap: wrap;
                    width: 100%;
                }
                .report-link-input {
                    font-family: monospace;
                    font-size: 0.85em;
                    background: rgba(255,255,255,0.06);
                    border: 1px solid rgba(255,255,255,0.15);
                    color: inherit;
                    padding: 0.3em 0.6em;
                    border-radius: 3px;
                    flex: 1;
                    min-width: 0;
                }
                .report-stat-strip {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 0.5em;
                    margin: 0.75em 0 1.25em;
                }
                .stat-pill {
                    font-size: 0.82em;
                    opacity: 0.7;
                    background: rgba(255,255,255,0.06);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 3px;
                    padding: 0.2em 0.6em;
                    white-space: nowrap;
                }
                .report-row-hidden { display: none; }
                #show-all-rows-btn { margin-top: 0.75em; }
                @media print {
                    .report-row-hidden { display: table-row !important; }
                    #show-all-rows-btn { display: none; }
                }
            </style>

            <?php
            // Pre-compute values needed for stat strip (also used below)
            $has_ranges = !empty($report['asn_ranges']);
            $asn_count  = count($report['asn_ranges'] ?? []);
            $abuse_data = compute_abuseipdb_callout($top25);
            ?>

            <!-- Row 1: Title + stats -->
            <div class="report-header-row">
                <h2>Threat Report</h2>
                <p class="report-header-stats">
                    <?php echo number_format($total); ?> IPs &middot;
                    <?php echo htmlspecialchars(date('F j, Y', strtotime($gen_date)), ENT_QUOTES, 'UTF-8'); ?>
                </p>
            </div>

            <!-- Row 2: Verdict badge + Print/Copy buttons -->
            <div class="report-header-row report-verdict-row">
                <p class="asn-verdict asn-verdict--<?php echo $verdict_lc; ?>">
                    <?php echo $verdict; ?> THREAT
                </p>
                <div style="display:flex;gap:0.5em;align-items:center">
                    <button onclick="window.print()" class="button small alt print-report-btn" style="white-space:nowrap">Print / Save as PDF</button>
                    <button id="copy-link-header-btn" class="button small alt" style="white-space:nowrap">Copy link</button>
                </div>
            </div>

            <!-- Stat strip -->
            <div class="report-stat-strip">
                <span class="stat-pill"><?php echo number_format($total); ?> IPs analyzed</span>
                <?php if ((int)($report['scanning_pct'] ?? 0) > 0): ?>
                <span class="stat-pill"><?php echo (int)$report['scanning_pct']; ?>% scanning/proxy</span>
                <?php endif; ?>
                <?php if ($asn_count > 0): ?>
                <span class="stat-pill"><?php echo $asn_count; ?> ASN<?php echo $asn_count === 1 ? '' : 's'; ?></span>
                <?php endif; ?>
                <?php if ($abuse_data !== null): ?>
                <span class="stat-pill">AbuseIPDB avg <?php echo $abuse_data['avg']; ?>%</span>
                <?php endif; ?>
            </div>

            <?php if ($verdict === 'LOW'): ?>
            <p style="opacity:0.7;font-size:0.9em">No high-confidence threats detected. Scores below confirm low risk.</p>
            <?php endif; ?>
            <!-- Threat narrative (supersedes verdict_text when present) -->
            <?php
            $narrative = generate_threat_narrative($verdict, $report['asn_ranges'] ?? [], (int)($report['scanning_pct'] ?? 0));
            if ($narrative !== ''): ?>
            <p><?php echo $narrative; ?></p>
            <?php else: ?>
            <p><?php echo htmlspecialchars($verdict_text, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <!-- AbuseIPDB callout -->
            <?php if ($abuse_data !== null): ?>
            <p class="abuseipdb-callout">
                AbuseIPDB independently verified <strong><?php echo $abuse_data['count']; ?></strong> of <?php echo $abuse_data['total']; ?> top IPs as known attackers (average confidence: <strong><?php echo $abuse_data['avg']; ?>%</strong>).
            </p>
            <?php endif; ?>

            <!-- ASN Ranges + Block Rules layout:
                 ≥3 ASNs → two-column grid (sticky right col floats alongside long list)
                 <3 ASNs → full-width stack (avoids empty space next to short list)
                 no ranges → block rules full-width only -->
            <div id="block-rules"></div>
            <?php $use_columns = $has_ranges && $asn_count >= 3; ?>
            <?php if ($use_columns): ?>
            <div class="ranges-rules-grid">
                <div class="ranges-col">
                    <h3>ASN Ranges to Block</h3>
                    <?php foreach ($report['asn_ranges'] as $group):
                        $shown = count($group['cidrs']);
                        $total_ranges = $group['total'];
                    ?>
                    <div class="asn-range-group">
                        <div class="asn-range-header">
                            <strong><?php echo htmlspecialchars($group['asn'], ENT_QUOTES, 'UTF-8'); ?></strong>
                            <?php if ($group['org']): ?>
                            <span class="asn-range-org"><?php echo htmlspecialchars($group['org'], ENT_QUOTES, 'UTF-8'); ?></span>
                            <?php endif; ?>
                            <?php if ($total_ranges > $shown): ?>
                            <span class="asn-range-count"><?php echo $shown; ?> of <?php echo number_format($total_ranges); ?> &mdash; all in download</span>
                            <?php else: ?>
                            <span class="asn-range-count"><?php echo $total_ranges; ?> range<?php echo $total_ranges === 1 ? '' : 's'; ?></span>
                            <?php endif; ?>
                        </div>
                        <div class="cidr-chips">
                            <?php foreach ($group['cidrs'] as $cidr): ?>
                            <span class="cidr-chip"><?php echo htmlspecialchars($cidr, ENT_QUOTES, 'UTF-8'); ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <div class="rules-col">
            <?php else: ?>
            <?php if ($has_ranges): ?>
            <div class="ranges-stack">
                <h3>ASN Ranges to Block</h3>
                <?php foreach ($report['asn_ranges'] as $group):
                    $shown = count($group['cidrs']);
                    $total_ranges = $group['total'];
                ?>
                <div class="asn-range-group">
                    <div class="asn-range-header">
                        <strong><?php echo htmlspecialchars($group['asn'], ENT_QUOTES, 'UTF-8'); ?></strong>
                        <?php if ($group['org']): ?>
                        <span class="asn-range-org"><?php echo htmlspecialchars($group['org'], ENT_QUOTES, 'UTF-8'); ?></span>
                        <?php endif; ?>
                        <?php if ($total_ranges > $shown): ?>
                        <span class="asn-range-count"><?php echo $shown; ?> of <?php echo number_format($total_ranges); ?> &mdash; all in download</span>
                        <?php else: ?>
                        <span class="asn-range-count"><?php echo $total_ranges; ?> range<?php echo $total_ranges === 1 ? '' : 's'; ?></span>
                        <?php endif; ?>
                    </div>
                    <div class="cidr-chips">
                        <?php foreach ($group['cidrs'] as $cidr): ?>
                        <span class="cidr-chip"><?php echo htmlspecialchars($cidr, ENT_QUOTES, 'UTF-8'); ?></span>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
            <div class="block-rules-fullwidth">
            <?php endif; ?>
                    <h3 class="block-rules-heading">Block Rules</h3>
                    <p style="font-size:0.9em;opacity:0.7;margin-bottom:0.5em">
                        Click a format to preview, then copy or download.
                    </p>
                    <div class="hosting-callout">
                        <strong>No console/SSH access?</strong> Block IPs directly from your hosting panel instead:
                        <ul class="hosting-callout-links">
                            <li><a href="https://docs.cpanel.net/cpanel/security/ip-blocker/" target="_blank" rel="noopener">cPanel IP Blocker</a> <span class="hosting-note">(Namecheap, GoDaddy, Bluehost, most shared hosts)</span></li>
                            <li><a href="https://www.plesk.com/kb/support/how-to-block-an-ip-address-in-plesk-firewall/" target="_blank" rel="noopener">Plesk IP Ban</a> <span class="hosting-note">(another common shared host panel)</span></li>
                            <li><a href="https://developers.cloudflare.com/waf/tools/ip-access-rules/" target="_blank" rel="noopener">Cloudflare IP Access Rules</a> <span class="hosting-note">(if your site is proxied through Cloudflare)</span></li>
                            <li><a href="https://docs.digitalocean.com/products/networking/firewalls/" target="_blank" rel="noopener">DigitalOcean Cloud Firewall</a></li>
                            <li><a href="https://docs.hetzner.com/cloud/firewalls/overview/" target="_blank" rel="noopener">Hetzner Cloud Firewall</a></li>
                        </ul>
                    </div>
                    <?php include_block_rules_tabs($token, $has_ranges, $report); ?>
            <?php if ($use_columns): ?>
                </div>
            </div>
            <?php else: ?>
            </div>
            <?php endif; ?>
            <script>
            function switchBlockTab(name) {
                document.querySelectorAll('.block-rules-tab').forEach(function(t) {
                    var active = t.id === 'tab-' + name;
                    t.classList.toggle('active', active);
                    t.setAttribute('aria-selected', active ? 'true' : 'false');
                });
                document.querySelectorAll('.block-rules-panel').forEach(function(p) {
                    p.style.display = p.id === 'panel-' + name ? '' : 'none';
                });
                window.umami && umami.track('report_tab_switch', { tab: name });
            }
            document.querySelectorAll('.block-rules-tab:not(.brt-disabled)').forEach(function(t) {
                t.addEventListener('click', function() { switchBlockTab(this.id.replace('tab-', '')); });
                t.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); switchBlockTab(this.id.replace('tab-', '')); }
                });
            });
            // Track downloads via format-actions links
            document.querySelectorAll('.format-actions a.button[href]').forEach(function(a) {
                a.addEventListener('click', function() {
                    var fmt = (this.getAttribute('href') || '').replace(/.*format=/, '');
                    var scope = this.closest('#panel-by-range') ? 'by-range' : 'by-ip';
                    window.umami && umami.track('report_download', { format: fmt, scope: scope });
                });
            });
            // Format-toggle: accordion — one open at a time within each tab panel
            document.querySelectorAll('.format-toggle').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var target = document.getElementById(btn.dataset.target);
                    var opening = target.hidden;
                    // Close all siblings in the same panel first
                    var panel = btn.closest('.block-rules-panel');
                    panel.querySelectorAll('.format-toggle').forEach(function(other) {
                        var otherTarget = document.getElementById(other.dataset.target);
                        otherTarget.hidden = true;
                        other.setAttribute('aria-expanded', 'false');
                        other.innerHTML = '&#9656; ' + other.dataset.label;
                    });
                    // Then open the clicked one (unless it was already open)
                    if (opening) {
                        target.hidden = false;
                        btn.setAttribute('aria-expanded', 'true');
                        btn.innerHTML = '&#9662; ' + btn.dataset.label;
                        window.umami && umami.track('report_script_preview', { format: btn.dataset.target.replace('fmt-', '') });
                    }
                });
            });
            // Copy button: copy script content to clipboard
            document.querySelectorAll('.copy-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var pre = btn.closest('.format-block').querySelector('pre');
                    var text = pre.textContent;
                    if (navigator.clipboard && window.isSecureContext) {
                        navigator.clipboard.writeText(text).then(function() {
                            btn.textContent = 'Copied!';
                            setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
                        });
                    } else {
                        var sel = window.getSelection();
                        var range = document.createRange();
                        range.selectNodeContents(pre);
                        sel.removeAllRanges();
                        sel.addRange(range);
                        document.execCommand('copy');
                        sel.removeAllRanges();
                        btn.textContent = 'Copied!';
                        setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
                    }
                });
            });
            </script>

            <!-- Block script filter -->
            <?php if (!empty($all_ips)): ?>
            <div id="report-filter" role="region" aria-label="Block script filter">
                <details id="report-filter-details">
                    <summary id="report-filter-summary">Block Script Filter &mdash; <span id="report-filter-count"><?php echo $blockable_count; ?></span> of <span id="report-filter-total"><?php echo $blockable_count; ?></span> IPs in block scripts</summary>
                    <div id="report-filter-layout">
                        <div id="report-filter-categories">
                            <strong>ASN Categories</strong>
                            <?php
                            $cat_labels = ['scanning' => 'Scanning', 'vpn' => 'VPN/Proxy'];
                            foreach ($cat_labels as $cat => $label):
                                if (($all_cats[$cat] ?? 0) === 0) continue;
                                $cat_safe = htmlspecialchars($cat, ENT_QUOTES, 'UTF-8');
                            ?>
                            <label class="cat-<?php echo $cat_safe; ?>"><input type="checkbox" class="report-filter-category" value="<?php echo $cat_safe; ?>" checked><span class="chip-label"><?php echo htmlspecialchars($label, ENT_QUOTES, 'UTF-8'); ?></span> <span class="chip-count">(<?php echo $all_cats[$cat]; ?>)</span></label>
                            <?php endforeach; ?>
                        </div>
                        <?php if (!empty($all_ctries)): ?>
                        <div id="report-filter-countries">
                            <strong>Countries <span class="chip-hint">⇧ multi-select</span></strong>
                            <div class="filter-chips">
                            <?php foreach ($all_ctries as $cc => $count):
                                $cc_safe = htmlspecialchars($cc, ENT_QUOTES, 'UTF-8');
                            ?>
                                <label><input type="checkbox" class="report-filter-country" value="<?php echo $cc_safe; ?>" checked><span class="chip-label"><?php echo $cc_safe; ?></span> <span class="chip-count">(<?php echo $count; ?>)</span></label>
                            <?php endforeach; ?>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </details>
            </div>
            <script>
            (function() {
                var allIps = window.reportAllIps || [];
                if (!allIps.length) return;

                var blockCats = ['scanning', 'vpn'];
                var today = new Date().toISOString().slice(0, 10);

                function getFilteredIps() {
                    var checkedCats = {};
                    document.querySelectorAll('.report-filter-category:checked').forEach(function(cb) {
                        checkedCats[cb.value] = true;
                    });
                    var checkedCtries = {};
                    document.querySelectorAll('.report-filter-country:checked').forEach(function(cb) {
                        checkedCtries[cb.value] = true;
                    });
                    return allIps.filter(function(e) {
                        var cat = e.classification || 'unknown';
                        var cc  = e.country || '';
                        var catOk = checkedCats[cat];
                        // If no country chips exist (all_ctries empty), skip country filter
                        var noCtryChips = document.querySelectorAll('.report-filter-country').length === 0;
                        var ctryOk = noCtryChips || (cc === '' ? true : checkedCtries[cc]);
                        return catOk && ctryOk;
                    });
                }

                function getFilteredBlockIps() {
                    return getFilteredIps()
                        .filter(function(e) { return blockCats.indexOf(e.classification || '') !== -1; })
                        .sort(function(a, b) { return (b.freq || 1) - (a.freq || 1); })
                        .map(function(e) { return e.ip; });
                }

                function genIptables(ips) {
                    return '#!/bin/bash\n# ip2geo threat report \u2014 iptables block rules\n# Generated: ' + today + '\n# Block ' + ips.length + ' IPs flagged as scanning / proxy infrastructure\n\nset -euo pipefail\n' +
                        ips.map(function(ip) { return 'iptables -A INPUT -s ' + ip + ' -j DROP'; }).join('\n') + '\n';
                }

                function genUfw(ips) {
                    return '#!/bin/bash\n# ip2geo threat report \u2014 ufw block rules\n# Generated: ' + today + '\n# Block ' + ips.length + ' IPs flagged as scanning / proxy infrastructure\n\nset -euo pipefail\n' +
                        ips.map(function(ip) { return 'ufw deny from ' + ip + ' to any'; }).join('\n') + '\n';
                }

                function genNginx(ips) {
                    return '# ip2geo threat report \u2014 nginx geo block (individual IPs)\n# Generated: ' + today + '\n# Block ' + ips.length + ' IPs flagged as scanning / proxy infrastructure\n# Usage: include this file inside a geo $blocked_ip { } block in nginx.conf\n\ndefault 0;\n' +
                        ips.map(function(ip) { return ip + ' 1;'; }).join('\n') + '\n';
                }

                function triggerDownload(content, filename) {
                    var blob = new Blob([content], {type: 'text/plain'});
                    var url  = URL.createObjectURL(blob);
                    var a    = document.createElement('a');
                    a.href     = url;
                    a.download = filename;
                    a.click();
                    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
                }

                // Which chip values exist (to know which categories/countries are filterable)
                var allCatChips  = {};
                document.querySelectorAll('.report-filter-category').forEach(function(cb) { allCatChips[cb.value]  = true; });
                var allCtryChips = {};
                document.querySelectorAll('.report-filter-country').forEach(function(cb)  { allCtryChips[cb.value] = true; });

                function updateCount() {
                    var checkedCats   = {};
                    document.querySelectorAll('.report-filter-category:checked').forEach(function(cb) { checkedCats[cb.value]   = true; });
                    var checkedCtries = {};
                    document.querySelectorAll('.report-filter-country:checked').forEach(function(cb)  { checkedCtries[cb.value] = true; });

                    // Filter top-25 table rows; track visible count (skip collapsed rows)
                    var visibleRows = 0;
                    document.querySelectorAll('.report-table tbody tr').forEach(function(row) {
                        if (row.classList.contains('report-row-hidden')) return;
                        var cat = row.dataset.category || '';
                        var cc  = row.dataset.country  || '';
                        var catOk  = !allCatChips[cat]  || checkedCats[cat];
                        var ctryOk = cc === '' || !allCtryChips[cc] || checkedCtries[cc];
                        var show = catOk && ctryOk;
                        row.style.display = show ? '' : 'none';
                        if (show) visibleRows++;
                    });

                    // Update table "showing X of Y" counter
                    var tableCount = document.getElementById('report-table-count');
                    if (tableCount) tableCount.textContent = visibleRows;

                    // Update chip count badges: cross-filter counts from allIps
                    // Category badge = IPs passing the current country filter
                    // Country badge  = IPs passing the current category filter
                    var catCounts = {}, ctryCounts = {};
                    allIps.forEach(function(e) {
                        var cat = e.classification || 'unknown';
                        var cc  = e.country || '';
                        var catActive  = !allCatChips[cat]  || checkedCats[cat];
                        var ctryActive = cc === '' || !allCtryChips[cc] || checkedCtries[cc];
                        if (allCatChips[cat]  && ctryActive)  catCounts[cat]  = (catCounts[cat]  || 0) + 1;
                        if (allCtryChips[cc]  && catActive)   ctryCounts[cc]  = (ctryCounts[cc]  || 0) + 1;
                    });
                    document.querySelectorAll('.report-filter-category').forEach(function(cb) {
                        var countEl = cb.closest('label') && cb.closest('label').querySelector('.chip-count');
                        if (countEl) countEl.textContent = '(' + (catCounts[cb.value] || 0) + ')';
                    });
                    document.querySelectorAll('.report-filter-country').forEach(function(cb) {
                        var countEl = cb.closest('label') && cb.closest('label').querySelector('.chip-count');
                        if (countEl) countEl.textContent = '(' + (ctryCounts[cb.value] || 0) + ')';
                    });

                    // Update block script IP count
                    var blockIps = getFilteredBlockIps();
                    var countEl  = document.getElementById('report-filter-count');
                    if (countEl) countEl.textContent = blockIps.length;
                }

                // Intercept "Block by IP" download buttons
                document.querySelectorAll('#panel-by-ip .button[data-format]').forEach(function(btn) {
                    btn.addEventListener('click', function(e) {
                        e.preventDefault();
                        var fmt  = this.dataset.format;
                        var ips  = getFilteredBlockIps();
                        var content = '';
                        var filename = '';
                        if (fmt === 'sh-iptables') {
                            content  = genIptables(ips);
                            filename = 'block-iptables.sh';
                        } else if (fmt === 'sh-ufw') {
                            content  = genUfw(ips);
                            filename = 'block-ufw.sh';
                        } else if (fmt === 'nginx-ips') {
                            content  = genNginx(ips);
                            filename = 'block-nginx-ips.conf';
                        }
                        if (content) {
                            triggerDownload(content, filename);
                            window.umami && umami.track('report_download', { format: fmt, scope: 'by-ip' });
                        }
                    });
                });

                // Wire up filter chips
                document.querySelectorAll('.report-filter-category, .report-filter-country').forEach(function(cb) {
                    cb.addEventListener('change', updateCount);
                });

                // Country chip clicks: exclusive-select / shift+click multi-select
                // Plain click  → show ONLY that country (click again to restore all).
                // Shift+click  → toggle this country in/out; restore all if nothing left.
                document.addEventListener('click', function(e) {
                    var label = e.target && e.target.closest('#report-filter-countries label');
                    if (!label) return;
                    e.preventDefault();
                    var clicked = label.querySelector('input[type="checkbox"]');
                    if (!clicked) return;
                    var all = Array.from(document.querySelectorAll('.report-filter-country'));
                    if (e.shiftKey) {
                        clicked.checked = !clicked.checked;
                        if (!all.some(function(i) { return i.checked; })) {
                            all.forEach(function(i) { i.checked = true; });
                        }
                    } else {
                        var soloActive = all.filter(function(i) { return i.checked; }).length === 1 && clicked.checked;
                        if (soloActive) {
                            all.forEach(function(i) { i.checked = true; });
                        } else {
                            all.forEach(function(i) { i.checked = false; });
                            clicked.checked = true;
                        }
                    }
                    updateCount();
                });

                // Initial count
                updateCount();
            })();
            </script>
            <?php endif; ?>

            <!-- Top 25 table -->
            <h3 id="top-sources">Top Threat Sources <span id="report-table-summary" style="font-size:0.6em;font-weight:normal;opacity:0.6;margin-left:0.5em">— showing <span id="report-table-count"><?php echo count($top25); ?></span> of <span id="report-table-total"><?php echo count($top25); ?></span></span></h3>
            <?php if (empty($top25)): ?>
                <p>No IP data available.</p>
            <?php else: ?>
            <div class="table-wrapper" style="overflow-x:auto">
            <table class="report-table">
                <thead>
                    <tr>
                        <th scope="col" style="font-family:monospace">IP</th>
                        <th scope="col">ASN Org</th>
                        <th scope="col">Category</th>
                        <th scope="col" title="Times this IP appeared in the submitted log">Hits</th>
                        <th scope="col">AbuseIPDB</th>
                        <?php if ($data_consent === 1): ?>
                        <th scope="col" title="How many other ip2geo reports contained this IP this week — corroborates active threats">Community</th>
                        <?php endif; ?>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($top25 as $i => $entry):
                    $cat = $entry['classification'] ?? 'unknown';
                    $score = $entry['abuse_score'] ?? null;
                    $freq = $entry['freq'] ?? 1;
                    $asn_org_full = ($entry['asn'] ?? '') . ($entry['asn'] && ($entry['asn_org'] ?? '') ? ' ' : '') . ($entry['asn_org'] ?? '');
                    $row_class = $i >= 10 ? ' class="report-row-hidden"' : '';
                ?>
                    <tr<?php echo $row_class; ?> data-category="<?php echo htmlspecialchars($cat, ENT_QUOTES, 'UTF-8'); ?>" data-country="<?php echo htmlspecialchars($entry['country'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                        <td style="font-family:monospace"><?php echo htmlspecialchars($entry['ip'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                        <td class="cell-asn-org" title="<?php echo htmlspecialchars($asn_org_full, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($asn_org_full, ENT_QUOTES, 'UTF-8'); ?></td>
                        <td class="asn-category asn-category--<?php echo htmlspecialchars($cat, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($cat, ENT_QUOTES, 'UTF-8'); ?></td>
                        <td style="font-family:monospace"><?php echo $freq > 1 ? '<strong>' . $freq . 'x</strong>' : '1x'; ?></td>
                        <td><?php echo $score !== null ? htmlspecialchars((string)$score, ENT_QUOTES, 'UTF-8') : '<span style="opacity:0.4">—</span>'; ?></td>
                        <?php if ($data_consent === 1):
                            $ip = $entry['ip'] ?? '';
                            $this_week_count = (int)($community_data['ip_stats'][$ip] ?? 0);
                            $fs_date = $community_data['first_seen'][$ip] ?? null;
                            $days_ago = $fs_date ? max(0, (int)floor((time() - strtotime($fs_date)) / 86400)) : null;
                            $tooltip = $days_ago !== null ? ' title="First seen in community data: ' . $days_ago . ' day' . ($days_ago === 1 ? '' : 's') . ' ago"' : '';
                            if ($this_week_count < 3): ?>
                        <td><span style="opacity:0.4">—</span></td>
                        <?php else: ?>
                        <td<?php echo $tooltip; ?>><?php echo $this_week_count; ?> reports</td>
                        <?php endif; ?>
                        <?php endif; ?>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <?php if (count($top25) > 10): ?>
            <button id="show-all-rows-btn" class="button small alt">Show all <?php echo count($top25); ?> IPs</button>
            <script>
            document.getElementById('show-all-rows-btn').addEventListener('click', function() {
                document.querySelectorAll('.report-row-hidden').forEach(function(r) { r.classList.remove('report-row-hidden'); });
                this.style.display = 'none';
            });
            </script>
            <?php endif; ?>
            <p style="font-size:0.8em;opacity:0.6">
                Top 25 by weighted frequency (scanning/VPN weighted 2&times;). Hits = times
                this IP appeared in your submitted log. AbuseIPDB score 0–100; a score of 0
                means no community reports on file — common for Asian ISP ranges that are
                underreported in AbuseIPDB, not a signal the IP is clean.
                <?php if ($report['abuseipdb_note'] ?? null): ?>
                    <?php echo htmlspecialchars($report['abuseipdb_note'], ENT_QUOTES, 'UTF-8'); ?>
                <?php endif; ?>
            </p>
            <?php if ($data_consent === 1): ?>
            <p style="font-size:0.85em;opacity:0.75">
                Community column = number of other ip2geo reports that contained this IP this week.
                <a href="/intel.php" target="_blank" rel="noopener noreferrer">Download the community block list &rarr;</a>
            </p>
            <?php endif; ?>
            <?php endif; ?>

            <!-- Community Intel (demo preview / consent / opted-in) -->
            <?php if ($is_demo): ?>
            <div style="background:rgba(108,184,122,0.12);border-left:3px solid #6cb87a;padding:0.8em 1em;margin-bottom:1.5em;font-size:0.9em">
                <strong>Community Intel</strong> <span style="opacity:0.6;font-size:0.85em;margin-left:0.3em">Preview</span>
                <p style="margin:0.4em 0 0.7em">Community Intel is available on paid reports. When you opt in, ip2geo cross-references your IPs against anonymized data from other users this week. The Community column shows how many other ip2geo reports contained the same IP &mdash; corroborating active threats and flagging escalating campaigns.</p>
                <p style="margin:0 0 0.4em;opacity:0.85;font-size:0.9em">This is what the Community column looks like in the Top Threat Sources table:</p>
                <table style="width:100%;font-size:0.85em;border-collapse:collapse">
                    <thead><tr style="opacity:0.6"><th style="text-align:left;padding:0.2em 0.6em 0.2em 0;font-weight:normal">IP</th><th style="text-align:left;padding:0.2em 0.6em;font-weight:normal">Category</th><th style="text-align:left;padding:0.2em 0;font-weight:normal">Community</th></tr></thead>
                    <tbody>
                        <tr><td style="padding:0.15em 0.6em 0.15em 0;font-family:monospace;opacity:0.8">185.220.101.x</td><td style="padding:0.15em 0.6em">Scanning</td><td style="padding:0.15em 0">23 reports</td></tr>
                        <tr><td style="padding:0.15em 0.6em 0.15em 0;font-family:monospace;opacity:0.8">193.32.162.x</td><td style="padding:0.15em 0.6em">VPN/Proxy</td><td style="padding:0.15em 0">8 reports</td></tr>
                        <tr><td style="padding:0.15em 0.6em 0.15em 0;font-family:monospace;opacity:0.8">192.168.x.x</td><td style="padding:0.15em 0.6em">Residential</td><td style="padding:0.15em 0"><span style="opacity:0.4">&mdash;</span></td></tr>
                    </tbody>
                </table>
                <p style="font-size:0.85em;opacity:0.6;margin:0.6em 0 0.75em">Residential IPs are never collected. 52-week retention. <a href="/privacy.php" target="_blank" rel="noopener noreferrer">Privacy policy</a></p>
                <a href="/" class="button small">Try with your own IPs &rarr;</a>
            </div>
            <?php endif; ?>

            <?php if (!$is_demo && ($data_consent === null || $data_consent === 0)): ?>
            <div id="community-consent-banner" class="community-intel-banner" style="background:rgba(108,184,122,0.12);border-left:3px solid #6cb87a;padding:0.8em 1em;margin-bottom:1.5em;font-size:0.9em">
                <?php if ($data_consent === 0): ?>
                <div id="consent-full" style="display:none">
                <?php else: ?>
                <div id="consent-full">
                <?php endif; ?>
                    <strong>Community Intel &mdash; opt in</strong>
                    <p style="margin:0.4em 0 0.8em">Share anonymized network and IP data to see how your traffic compares to this week's global attack trends. <a href="/privacy.php" target="_blank" rel="noopener noreferrer" style="opacity:0.7;font-size:0.9em">Privacy policy</a></p>
                    <div style="display:flex;gap:0.5em;flex-wrap:wrap">
                        <button class="button small" id="consent-yes-btn">Opt in &mdash; show me the comparison</button>
                        <button class="button small alt" id="consent-no-btn">No thanks</button>
                    </div>
                    <p style="margin:0.6em 0 0;font-size:0.82em;opacity:0.55">Community data is currently limited as this feature grows &mdash; your opt-in helps build it.</p>
                </div>
                <div id="consent-collapsed" style="<?php echo $data_consent === 0 ? '' : 'display:none;'; ?>font-size:0.9em;opacity:0.75">
                    Community Intel &mdash; you opted out.
                    <a id="consent-reconsider-btn" tabindex="0" style="color:inherit;text-decoration:underline;cursor:pointer;margin-left:0.2em">Change your mind?</a>
                </div>
            </div>
            <script>
            (function() {
                var token = <?php echo json_encode($token); ?>;
                function postConsent(consent, callback) {
                    var fd = new FormData();
                    fd.append('token', token);
                    fd.append('consent', String(consent));
                    fetch('/community-consent.php', { method: 'POST', body: fd })
                        .then(function(r) { return r.json(); })
                        .then(callback)
                        .catch(function() {});
                }
                function showCollapsed() {
                    document.getElementById('consent-full').style.display = 'none';
                    document.getElementById('consent-collapsed').style.display = '';
                }
                function showFull() {
                    document.getElementById('consent-collapsed').style.display = 'none';
                    document.getElementById('consent-full').style.display = '';
                    document.getElementById('consent-no-btn').disabled = false;
                }
                document.getElementById('consent-yes-btn').addEventListener('click', function() {
                    var btn = this;
                    btn.disabled = true;
                    btn.textContent = 'Saving\u2026';
                    postConsent(1, function(data) {
                        if (!data.ok) return;
                        var banner = document.getElementById('community-consent-banner');
                        var html = '<div class="community-intel-banner" style="background:rgba(108,184,122,0.12);border-left:3px solid #6cb87a;padding:0.8em 1em;margin-bottom:1.5em;font-size:0.9em">';
                        html += '<strong>&#10003; Thanks for contributing!</strong>';
                        if (data.top_cidrs && data.top_cidrs.length) {
                            html += '<p style="margin:0.5em 0 0.3em;opacity:0.85">Top reported ranges in the past 7 days:</p>';
                            html += '<ul style="margin:0;padding-left:1.5em">';
                            data.top_cidrs.slice(0, 3).forEach(function(c) {
                                html += '<li><code>' + c.cidr + '</code> &mdash; ' + c.org + ' (' + c.report_count + ' report' + (c.report_count === 1 ? '' : 's') + ')</li>';
                            });
                            html += '</ul>';
                        } else {
                            html += '<p style="margin:0.5em 0 0.3em;opacity:0.85">The community dataset is still in its early days &mdash; data will grow as more users opt in. You\'ll get richer comparisons on future reports as the dataset builds.</p>';
                        }
                        html += '<p style="margin:0.7em 0 0"><a href="" onclick="window.location.reload();return false;" class="button small">Refresh to view your community data &rarr;</a></p>';
                        html += '</div>';
                        banner.outerHTML = html;
                    });
                });
                document.getElementById('consent-no-btn').addEventListener('click', function() {
                    this.disabled = true;
                    postConsent(0, function() { showCollapsed(); });
                });
                document.getElementById('consent-reconsider-btn').addEventListener('click', function(e) {
                    e.preventDefault();
                    showFull();
                });
            })();
            </script>
            <?php endif; ?>

            <?php if (!$is_demo && $data_consent === 1):
                $community_has_data = false;
                if (!empty($community_data['ip_stats'])) {
                    foreach ($community_data['ip_stats'] as $ip_count) {
                        if ($ip_count >= 3) {
                            $community_has_data = true;
                            break;
                        }
                    }
                }
            ?>
            <div class="community-intel-banner" style="background:rgba(108,184,122,0.12);border-left:3px solid #6cb87a;padding:0.8em 1em;margin-bottom:1.5em;font-size:0.9em">
                <strong>&#10003; Thank you for contributing to Community Intel</strong>
                <?php if (!$community_has_data): ?>
                <p style="margin:0.4em 0 0;opacity:0.8">The community dataset is still in its early days &mdash; data will grow as more users opt in. Check back on future reports for richer comparisons.</p>
                <?php else: ?>
                <p style="margin:0.4em 0 0;opacity:0.8">Your data is contributing to the community feed. See the Community column in the Top Threat Sources table above.</p>
                <?php endif; ?>
            </div>
            <?php endif; ?>

            <!-- Share link + expiry -->
            <hr />
            <p>
                <button id="share-link-btn" class="button small">&#128279; Share this report</button>
            </p>
            <p style="margin-top:1em">
                <a href="/?view_token=<?php echo urlencode($token); ?>#results" class="button small alt">
                    View all <?php echo number_format($total); ?> IPs
                </a>
                &nbsp;
                <a href="/" class="button small alt">New Lookup</a>
            </p>
        </div>
    </section>
    <script>
    function copyReportLink(btn) {
        var cleanUrl = window.location.origin + window.location.pathname + '?token=' + <?php echo json_encode($token); ?>;
        navigator.clipboard.writeText(cleanUrl).then(function() {
            var orig = btn.innerHTML;
            btn.innerHTML = 'Copied!';
            setTimeout(function() { btn.innerHTML = orig; }, 2000);
        });
        window.umami && umami.track('report_copy_link');
    }
    document.getElementById('share-link-btn').addEventListener('click', function() {
        copyReportLink(this);
    });
    var headerCopyBtn = document.getElementById('copy-link-header-btn');
    if (headerCopyBtn) headerCopyBtn.addEventListener('click', function() { copyReportLink(this); });
    document.querySelectorAll('a[href*="view_token="]').forEach(function(a) {
        a.addEventListener('click', function() {
            window.umami && umami.track('report_view_all_ips');
        });
    });
    // Fire once on load — key conversion signal (paid vs demo, verdict distribution)
    window.addEventListener('load', function() {
        var total = <?php echo (int)$total; ?>;
        var bucket = total <= 10 ? '1-10' : total <= 50 ? '11-50' : total <= 200 ? '51-200'
                   : total <= 1000 ? '201-1000' : total <= 5000 ? '1001-5000' : '5000+';
        window.umami && umami.track('report_view', {
            is_demo:          <?php echo $is_demo ? 'true' : 'false'; ?>,
            verdict:          <?php echo json_encode(strtolower($verdict)); ?>,
            ip_count_bucket:  bucket
        });
<?php if ($is_new_redemption): ?>
        try {
            window.umami && umami.track('report_purchase', {
                revenue:         9.00,
                currency:        'USD',
                verdict:         <?php echo json_encode(strtolower($verdict)); ?>,
                ip_count_bucket: bucket
            });
        } catch(e) {}
<?php endif; ?>
    });
    </script>
    <?php render_page_close();
}

// ── Shared page layout ────────────────────────────────────────────────────────

/**
 * @param array $nav_items  Optional custom nav. Each entry: ['label' => '...', 'href' => '...']. Defaults to the full paid-report nav.
 */
function render_page_open(string $title, string $meta_desc = '', array $og = [], array $nav_items = []): void {
    $safe_title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $safe_desc  = $meta_desc
        ? htmlspecialchars($meta_desc, ENT_QUOTES, 'UTF-8')
        : 'ip2geo.org threat report — bulk IP geolocation and threat triage.';
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php if ($_SERVER['HTTP_HOST'] === 'ip2geo.org'): ?>
    <script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
    <?php endif; ?>
    <title><?php echo $safe_title; ?></title>
    <meta charset="utf-8" />
    <meta name="description" content="<?php echo $safe_desc; ?>" />
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
    <?php if (!empty($og)): ?>
    <meta property="og:title" content="<?php echo htmlspecialchars($og['title'] ?? $title, ENT_QUOTES, 'UTF-8'); ?>">
    <meta property="og:description" content="<?php echo htmlspecialchars($og['description'] ?? $safe_desc, ENT_QUOTES, 'UTF-8'); ?>">
    <meta property="og:url" content="<?php echo htmlspecialchars($og['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
    <meta property="og:image" content="https://ip2geo.org/assets/images/og-card.webp">
    <meta property="og:type" content="website">
    <?php endif; ?>
    <link rel="stylesheet" href="/assets/css/main.css" />
    <link rel="stylesheet" href="/assets/css/ip2geo-app.css" />
    <link rel="stylesheet" href="/assets/css/ip2geo-print.css" media="print" />
    <link rel="icon" href="/favicon.ico" />
    <noscript><link rel="stylesheet" href="/assets/css/noscript.css" /></noscript>
</head>
<body class="is-preload">
    <section id="sidebar">
        <div class="inner">
            <nav>
                <ul>
                    <?php
                    $default_nav = [
                        ['label' => 'Summary',      'href' => '#report'],
                        ['label' => 'Block Rules',   'href' => '#block-rules'],
                        ['label' => 'Top Sources',   'href' => '#top-sources'],
                        ['label' => '← New Lookup', 'href' => '/'],
                    ];
                    foreach (($nav_items ?: $default_nav) as $item):
                        $label = htmlspecialchars($item['label'], ENT_QUOTES, 'UTF-8');
                        $href  = htmlspecialchars($item['href'],  ENT_QUOTES, 'UTF-8');
                    ?>
                    <li><a href="<?php echo $href; ?>"><?php echo $label; ?></a></li>
                    <?php endforeach; ?>
                </ul>
            </nav>
        </div>
    </section>
    <div id="wrapper">
    <?php
}

function render_page_close(): void { ?>
    </div>
    <?php require __DIR__ . '/includes/footer.php'; ?>
    <script src="/assets/js/jquery.min.js"></script>
    <script src="/assets/js/jquery.scrollex.min.js"></script>
    <script src="/assets/js/jquery.scrolly.min.js"></script>
    <script src="/assets/js/browser.min.js"></script>
    <script src="/assets/js/breakpoints.min.js"></script>
    <script src="/assets/js/util.js"></script>
    <script src="/assets/js/main.js"></script>
</body>
</html>
    <?php
}
