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
    'SELECT token, submission_hash, ip_list_json, status,
            pending_expires_at, report_expires_at, report_json,
            notification_email, email_sent_at
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
        render_error('Payment verification failed. Please contact support@ip2geo.org with your token: ' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8'));
        exit;
    }

    // Guard: session_id must belong to this token
    if (($stripe_session->client_reference_id ?? '') !== $token) {
        error_log('ip2geo report.php: session_id/token mismatch for token ' . $token);
        mysqli_close($con);
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

if ($status === 'redeemed') {
    // Check 30-day expiry
    if ($row['report_expires_at'] && strtotime($row['report_expires_at']) < time()) {
        mysqli_close($con);
        render_error('This report has expired (30-day access window). Your data is no longer stored. If you need a fresh analysis, visit ip2geo.org and submit your IP list again.');
        exit;
    }
    // Serve cached report
    $report = json_decode($row['report_json'], true);
    $ip_data_for_render = json_decode($row['ip_list_json'], true) ?? [];
    $cached_email      = $row['notification_email'] ?? '';
    $cached_email_sent = $row['email_sent_at'] !== null;
    mysqli_close($con);
    maybe_serve_script_download($report, $token);
    render_report($report, $token, $row['report_expires_at'], $ip_data_for_render, $cached_email, $cached_email_sent);
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

// Store report + mark redeemed in one UPDATE
$report_json_str  = json_encode($report);
$report_expires   = date('Y-m-d H:i:s', strtotime('+30 days'));
$stmt = $con->prepare(
    'UPDATE reports
     SET status = "redeemed", report_json = ?, report_expires_at = ?
     WHERE token = ? AND status IN ("pending","paid")'
);
$stmt->bind_param('sss', $report_json_str, $report_expires, $token);
$stmt->execute();
$stmt->close();

$email_was_sent = false;
if ($notification_email !== '' && !empty($resend_api_key) && !empty($resend_from)) {
    $email_was_sent = send_report_email($con, $token, $notification_email, $report_expires, $resend_api_key, $resend_from);
}
mysqli_close($con);

maybe_serve_script_download($report, $token);
render_report($report, $token, $report_expires, $ip_data, $notification_email, $email_was_sent);
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

function maybe_serve_script_download(array $report, string $token): void {
    if (!isset($_GET['format'])) return;
    $fmt = $_GET['format'];
    $valid = ['sh-iptables', 'sh-ufw', 'sh-iptables-ranges', 'sh-ufw-ranges', 'nginx-ips', 'nginx-ranges', 'txt-ranges'];
    if (!in_array($fmt, $valid, true)) return;

    $ips = !empty($report['block_ips']) ? $report['block_ips'] : array_column($report['top25'], 'ip');

    // Flatten all CIDR ranges from asn_ranges groups
    $cidrs = [];
    foreach ($report['asn_ranges'] ?? [] as $group) {
        foreach ($group['cidrs'] as $cidr) {
            $cidrs[] = $cidr;
        }
    }

    if ($fmt === 'sh-iptables') {
        $lines    = array_map(fn($ip) => 'iptables -A INPUT -s ' . $ip . ' -j DROP', $ips);
        $preamble = '#!/bin/bash
# ip2geo threat report — iptables block rules
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($ips) . ' IPs flagged as scanning / proxy infrastructure

set -euo pipefail
';
        $filename    = 'block-iptables.sh';
        $content_type = 'text/x-sh';
        $body = $preamble . implode("\n", $lines) . "\n";
    } elseif ($fmt === 'sh-ufw') {
        $lines    = array_map(fn($ip) => 'ufw deny from ' . $ip . ' to any', $ips);
        $preamble = '#!/bin/bash
# ip2geo threat report — ufw block rules
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($ips) . ' IPs flagged as scanning / proxy infrastructure

set -euo pipefail
';
        $filename    = 'block-ufw.sh';
        $content_type = 'text/x-sh';
        $body = $preamble . implode("\n", $lines) . "\n";
    } elseif ($fmt === 'sh-iptables-ranges') {
        $lines    = array_map(fn($cidr) => 'iptables -A INPUT -s ' . $cidr . ' -j DROP', $cidrs);
        $preamble = '#!/bin/bash
# ip2geo threat report — iptables block rules (ASN ranges)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes

set -euo pipefail
';
        $filename    = 'block-iptables-ranges.sh';
        $content_type = 'text/x-sh';
        $body = $preamble . implode("\n", $lines) . "\n";
    } elseif ($fmt === 'sh-ufw-ranges') {
        $lines    = array_map(fn($cidr) => 'ufw deny from ' . $cidr . ' to any', $cidrs);
        $preamble = '#!/bin/bash
# ip2geo threat report — ufw block rules (ASN ranges)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes

set -euo pipefail
';
        $filename    = 'block-ufw-ranges.sh';
        $content_type = 'text/x-sh';
        $body = $preamble . implode("\n", $lines) . "\n";
    } elseif ($fmt === 'nginx-ips') {
        $lines = array_map(fn($ip) => $ip . ' 1;', $ips);
        $preamble = '# ip2geo threat report — nginx geo block (individual IPs)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($ips) . ' IPs flagged as scanning / proxy infrastructure
# Usage: include this file inside a geo $blocked_ip { } block in nginx.conf

default 0;
';
        $filename    = 'block-nginx-ips.conf';
        $content_type = 'text/plain';
        $body = $preamble . implode("\n", $lines) . "\n";
    } elseif ($fmt === 'nginx-ranges') {
        $lines = array_map(fn($cidr) => $cidr . ' 1;', $cidrs);
        $preamble = '# ip2geo threat report — nginx geo block (ASN ranges)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes
# Usage: include this file inside a geo $blocked_ip { } block in nginx.conf

default 0;
';
        $filename    = 'block-nginx-ranges.conf';
        $content_type = 'text/plain';
        $body = $preamble . implode("\n", $lines) . "\n";
    } else { // txt-ranges
        $preamble = '# ip2geo threat report — CIDR ranges (plain list)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes
# One range per line — paste into ipset, web firewall, or any blocklist tool
';
        $filename    = 'cidr-ranges.txt';
        $content_type = 'text/plain';
        $body = $preamble . implode("\n", $cidrs) . "\n";
    }

    header('Content-Type: ' . $content_type . '; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function include_block_rules_tabs(string $token, bool $has_ranges): void { ?>
            <div class="block-rules-tabs">
                <div class="block-rules-tablist" role="tablist" aria-label="Block by IP or by range">
                    <div class="block-rules-tab<?php echo $has_ranges ? ' active' : ''; ?>" id="tab-by-range" role="tab" tabindex="<?php echo $has_ranges ? '0' : '-1'; ?>" aria-selected="<?php echo $has_ranges ? 'true' : 'false'; ?>" aria-controls="panel-by-range"<?php echo $has_ranges ? '' : ' aria-disabled="true" title="No ASN ranges available for this report"'; ?>>Block by Range</div>
                    <div class="block-rules-tab<?php echo $has_ranges ? '' : ' active'; ?>" id="tab-by-ip" role="tab" tabindex="0" aria-selected="<?php echo $has_ranges ? 'false' : 'true'; ?>" aria-controls="panel-by-ip">Block by IP</div>
                </div>
                <div id="panel-by-range" class="block-rules-panel" role="tabpanel" aria-labelledby="tab-by-range"<?php echo $has_ranges ? '' : ' style="display:none"'; ?>>
                    <?php if ($has_ranges): ?>
                    <a href="/report.php?token=<?php echo urlencode($token); ?>&amp;format=sh-iptables-ranges"
                       class="button small">&#8595; block-iptables-ranges.sh</a>
                    <a href="/report.php?token=<?php echo urlencode($token); ?>&amp;format=sh-ufw-ranges"
                       class="button small">&#8595; block-ufw-ranges.sh</a>
                    <a href="/report.php?token=<?php echo urlencode($token); ?>&amp;format=nginx-ranges"
                       class="button small">&#8595; block-nginx-ranges.conf</a>
                    <a href="/report.php?token=<?php echo urlencode($token); ?>&amp;format=txt-ranges"
                       class="button small alt">&#8595; cidr-ranges.txt</a>
                    <?php else: ?>
                    <p style="font-size:0.9em;opacity:0.5;margin:0.6em 0">No ASN ranges available for this report.</p>
                    <?php endif; ?>
                </div>
                <div id="panel-by-ip" class="block-rules-panel" role="tabpanel" aria-labelledby="tab-by-ip"<?php echo $has_ranges ? ' style="display:none"' : ''; ?>>
                    <a href="/report.php?token=<?php echo urlencode($token); ?>&amp;format=sh-iptables"
                       class="button small" data-format="sh-iptables">&#8595; block-iptables.sh</a>
                    <a href="/report.php?token=<?php echo urlencode($token); ?>&amp;format=sh-ufw"
                       class="button small" data-format="sh-ufw">&#8595; block-ufw.sh</a>
                    <a href="/report.php?token=<?php echo urlencode($token); ?>&amp;format=nginx-ips"
                       class="button small" data-format="nginx-ips">&#8595; block-nginx-ips.conf</a>
                </div>
            </div>
<?php }

function render_error(string $msg): void {
    $title = 'Report Unavailable — ip2geo.org';
    render_page_open($title); ?>
    <section id="report" class="wrapper style4 fade-up">
        <div class="inner">
            <h2>Report Unavailable</h2>
            <p><?php echo htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?></p>
            <p><a href="/" class="button small">← Back to ip2geo</a></p>
        </div>
    </section>
    <?php render_page_close();
}

function render_report(array $report, string $token, ?string $expires_at, array $all_ips = [], string $notification_email = '', bool $email_sent = false): void {
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
            <div class="report-email-notice sent">
                <span>&#10003; Report link sent to <strong><?php echo htmlspecialchars(mask_email($notification_email), ENT_QUOTES, 'UTF-8'); ?></strong>. Check your inbox.</span>
            </div>
            <?php elseif ($token !== DEMO_TOKEN): ?>
            <?php
                $report_url   = 'https://ip2geo.org/report.php?token=' . urlencode($token);
                $resend_link  = '/send-report-link.php?token=' . urlencode($token);
            ?>
            <div class="report-email-notice save">
                <div style="width:100%">
                    <strong>Save your report link</strong> &mdash; it expires on <?php echo htmlspecialchars($expires_fmt ?? 'in 30 days', ENT_QUOTES, 'UTF-8'); ?>.
                    Bookmark it or <a href="<?php echo htmlspecialchars($resend_link, ENT_QUOTES, 'UTF-8'); ?>">email it to yourself</a>.
                    <div class="report-link-row">
                        <input class="report-link-input" id="rpt-link" type="text" readonly
                               value="<?php echo htmlspecialchars($report_url, ENT_QUOTES, 'UTF-8'); ?>">
                        <button class="button small alt" style="white-space:nowrap;padding:0.3em 0.8em"
                                onclick="var i=document.getElementById('rpt-link');i.select();document.execCommand('copy');this.textContent='Copied!'">Copy link</button>
                    </div>
                </div>
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
            </style>

            <!-- Row 1: Title + stats -->
            <div class="report-header-row">
                <h2>Threat Report</h2>
                <p class="report-header-stats">
                    <?php echo number_format($total); ?> IPs &middot;
                    <?php echo htmlspecialchars(date('F j, Y', strtotime($gen_date)), ENT_QUOTES, 'UTF-8'); ?>
                </p>
            </div>

            <!-- Row 2: Verdict badge + Print button -->
            <div class="report-header-row report-verdict-row">
                <p class="asn-verdict asn-verdict--<?php echo $verdict_lc; ?>">
                    <?php echo $verdict; ?> THREAT
                </p>
                <button onclick="window.print()" class="button small alt print-report-btn">Print / Save as PDF</button>
            </div>

            <?php if ($verdict === 'LOW'): ?>
            <p style="opacity:0.7;font-size:0.9em">No high-confidence threats detected. Scores below confirm low risk.</p>
            <?php endif; ?>
            <p><?php echo htmlspecialchars($verdict_text, ENT_QUOTES, 'UTF-8'); ?></p>

            <!-- Threat narrative -->
            <?php
            $narrative = generate_threat_narrative($verdict, $report['asn_ranges'] ?? [], (int)($report['scanning_pct'] ?? 0));
            if ($narrative !== ''): ?>
            <p><?php echo $narrative; ?></p>
            <?php endif; ?>

            <!-- AbuseIPDB callout -->
            <?php
            $abuse_data = compute_abuseipdb_callout($top25);
            if ($abuse_data !== null): ?>
            <p class="abuseipdb-callout">
                AbuseIPDB independently verified <strong><?php echo $abuse_data['count']; ?></strong> of <?php echo $abuse_data['total']; ?> top IPs as known attackers (average confidence: <strong><?php echo $abuse_data['avg']; ?>%</strong>).
            </p>
            <?php endif; ?>

            <!-- Analysis scope callout -->
            <?php if (!empty($report['asn_ranges'])): ?>
            <p style="font-size:0.85em;opacity:0.65">
                Analyzed <?php echo number_format($total); ?> IPs, verified top threats against AbuseIPDB, extracted CIDR prefixes from <?php echo count($report['asn_ranges']); ?> ASN<?php echo count($report['asn_ranges']) === 1 ? '' : 's'; ?>.
            </p>
            <?php endif; ?>

            <!-- What to do next -->
            <?php $has_ranges = !empty($report['asn_ranges']); ?>
            <div class="next-steps">
                <h3>What to do next</h3>
                <ol>
                    <?php if ($has_ranges): ?>
                    <li>Download a block script below, or copy the CIDR ranges and add them to your firewall directly — blocking by range is more resilient as IPs rotate.</li>
                    <?php else: ?>
                    <li>Download a block script below and run it on your server.</li>
                    <?php endif; ?>
                    <li>Verify in your firewall logs that traffic from these sources drops within a few minutes.</li>
                    <li>Check back in 48 hours: <a href="/">submit new logs</a> to confirm the blocking worked.</li>
                </ol>
            </div>

            <!-- ASN Ranges + Block Rules: side-by-side when ranges exist, Block Rules full-width otherwise -->
            <div id="block-rules"></div>
            <?php if ($has_ranges): ?>
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
                    <h3>Block Rules</h3>
                    <p style="font-size:0.9em;opacity:0.7;margin-bottom:1em">
                        Range-based rules stay valid as IPs rotate. Download a ready-to-run script, or plain text for paste-in to a web firewall or ipset.
                    </p>
                    <?php include_block_rules_tabs($token, $has_ranges); ?>
                </div>
            </div>
            <?php else: ?>
            <h3 class="block-rules-heading">Block Rules</h3>
            <?php include_block_rules_tabs($token, $has_ranges); ?>
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
                umami && umami.track('report_tab_switch', { tab: name });
            }
            document.querySelectorAll('.block-rules-tab:not(.brt-disabled)').forEach(function(t) {
                t.addEventListener('click', function() { switchBlockTab(this.id.replace('tab-', '')); });
                t.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); switchBlockTab(this.id.replace('tab-', '')); }
                });
            });
            // Track range-panel downloads (plain <a> tags, no JS intercept)
            document.querySelectorAll('#panel-by-range a.button[href]').forEach(function(a) {
                a.addEventListener('click', function() {
                    var fmt = (this.getAttribute('href') || '').replace(/.*format=/, '');
                    umami && umami.track('report_download', { format: fmt, scope: 'by-range' });
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

                    // Filter top-25 table rows; track visible count
                    var visibleRows = 0;
                    document.querySelectorAll('.report-table tbody tr').forEach(function(row) {
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
                            umami && umami.track('report_download', { format: fmt, scope: 'by-ip' });
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
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($top25 as $entry):
                    $cat = $entry['classification'] ?? 'unknown';
                    $score = $entry['abuse_score'] ?? null;
                    $freq = $entry['freq'] ?? 1;
                    $asn_org_full = ($entry['asn'] ?? '') . ($entry['asn'] && ($entry['asn_org'] ?? '') ? ' ' : '') . ($entry['asn_org'] ?? '');
                ?>
                    <tr data-category="<?php echo htmlspecialchars($cat, ENT_QUOTES, 'UTF-8'); ?>" data-country="<?php echo htmlspecialchars($entry['country'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                        <td style="font-family:monospace"><?php echo htmlspecialchars($entry['ip'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                        <td class="cell-asn-org" title="<?php echo htmlspecialchars($asn_org_full, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($asn_org_full, ENT_QUOTES, 'UTF-8'); ?></td>
                        <td class="asn-category asn-category--<?php echo htmlspecialchars($cat, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($cat, ENT_QUOTES, 'UTF-8'); ?></td>
                        <td style="font-family:monospace"><?php echo $freq > 1 ? '<strong>' . $freq . 'x</strong>' : '1x'; ?></td>
                        <td><?php echo $score !== null ? htmlspecialchars((string)$score, ENT_QUOTES, 'UTF-8') : '<span style="opacity:0.4">—</span>'; ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <p style="font-size:0.8em;opacity:0.6">
                Top 25 by weighted frequency (scanning/VPN weighted 2&times;). Hits = times
                this IP appeared in your submitted log. AbuseIPDB score 0–100; a score of 0
                means no community reports on file — common for Asian ISP ranges that are
                underreported in AbuseIPDB, not a signal the IP is clean.
                <?php if ($report['abuseipdb_note'] ?? null): ?>
                    <?php echo htmlspecialchars($report['abuseipdb_note'], ENT_QUOTES, 'UTF-8'); ?>
                <?php endif; ?>
            </p>
            <?php endif; ?>

            <!-- Share link + expiry -->
            <hr />
            <p>
                <button id="share-link-btn" class="button small">&#128279; Share this report</button>
            </p>
            <?php if ($expires_fmt && !$is_demo): ?>
            <p style="font-size:0.85em;opacity:0.6">
                Report expires: <?php echo htmlspecialchars($expires_fmt, ENT_QUOTES, 'UTF-8'); ?>.
                Save this link to access your report.
            </p>
            <?php endif; ?>

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
    document.getElementById('share-link-btn').addEventListener('click', function() {
        var cleanUrl = window.location.origin + window.location.pathname + '?token=' + <?php echo json_encode($token); ?>;
        navigator.clipboard.writeText(cleanUrl).then(function() {
            var btn = document.getElementById('share-link-btn');
            var orig = btn.innerHTML;
            btn.innerHTML = 'Link copied!';
            setTimeout(function() { btn.innerHTML = orig; }, 2000);
        });
        umami && umami.track('report_copy_link');
    });
    document.querySelectorAll('a[href*="view_token="]').forEach(function(a) {
        a.addEventListener('click', function() {
            umami && umami.track('report_view_all_ips');
        });
    });
    // Fire once on load — key conversion signal (paid vs demo, verdict distribution)
    window.addEventListener('load', function() {
        var total = <?php echo (int)$total; ?>;
        var bucket = total <= 10 ? '1-10' : total <= 50 ? '11-50' : total <= 200 ? '51-200'
                   : total <= 1000 ? '201-1000' : total <= 5000 ? '1001-5000' : '5000+';
        umami && umami.track('report_view', {
            is_demo:          <?php echo $is_demo ? 'true' : 'false'; ?>,
            verdict:          <?php echo json_encode(strtolower($verdict)); ?>,
            ip_count_bucket:  bucket
        });
    });
    </script>
    <?php render_page_close();
}

// ── Shared page layout ────────────────────────────────────────────────────────

function render_page_open(string $title, string $meta_desc = ''): void {
    $safe_title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $safe_desc  = $meta_desc
        ? htmlspecialchars($meta_desc, ENT_QUOTES, 'UTF-8')
        : 'ip2geo.org threat report — bulk IP geolocation and threat triage.';
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
    <title><?php echo $safe_title; ?></title>
    <meta charset="utf-8" />
    <meta name="description" content="<?php echo $safe_desc; ?>" />
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
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
                    <li><a href="#report">Summary</a></li>
                    <li><a href="#block-rules">Block Rules</a></li>
                    <li><a href="#top-sources">Top Sources</a></li>
                    <li><a href="/">← New Lookup</a></li>
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
