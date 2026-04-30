<?php
/**
 * Community Block List — /intel.php
 *
 * Public page showing the top CIDR ranges reported by opted-in ip2geo users
 * in the past 7 days. Data sourced from community_cidr_stats (via community-consent.php).
 *
 * Global threshold: 5 distinct opted-in reports in the past 7 days before data is shown.
 * Per-CIDR threshold: only CIDRs seen in 3+ independent reports are included.
 * Download formats: iptables / ufw / nginx / plain .txt (top 50 CIDRs).
 * No auth required. Updated continuously as users opt in.
 */

require __DIR__ . '/config.php';

header('X-Content-Type-Options: nosniff');

// ── Rolling 7-day window ──────────────────────────────────────────────────────
$cutoff   = gmdate('Y-m-d', strtotime('-7 days'));
$date_str = gmdate('Y-m-d');

// ── Detect download request early so it bypasses the page cache ───────────────
$fmt          = isset($_GET['format']) ? $_GET['format'] : '';
$valid_formats = ['iptables', 'ufw', 'nginx', 'txt'];
$is_download  = ($fmt !== '' && in_array($fmt, $valid_formats, true));

// ── APCu page cache (HTML only; downloads always bypass) ─────────────────────
// Cache key includes today's date — auto-invalidates at UTC midnight.
// TTL of 900 s (15 min) guards against stale data within the same day.
$_cache_key = 'intel_page_7d_' . $date_str;
if (!$is_download && function_exists('apcu_fetch')) {
    $cached = apcu_fetch($_cache_key, $_cache_hit);
    if ($_cache_hit) {
        echo $cached;
        exit;
    }
}

// ── DB connection ─────────────────────────────────────────────────────────────
$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    http_response_code(503);
    echo 'Database unavailable. Please try again shortly.';
    exit;
}

// ── Check threshold (min 5 distinct opted-in reports in past 7 days) ─────────
$thr_stmt = $con->prepare(
    'SELECT COALESCE(SUM(opted_in_reports), 0) AS total_reports
     FROM community_weekly_stats WHERE report_date >= ?'
);
$thr_stmt->bind_param('s', $cutoff);
$thr_stmt->execute();
$thr_row = $thr_stmt->get_result()->fetch_assoc();
$thr_stmt->close();

$total_reports = (int)($thr_row['total_reports'] ?? 0);
$has_data = $total_reports >= 5;

// ── Fetch top 50 CIDRs (rolling 7 days, ≥3 independent reports per CIDR) ────
//
// Quality filters applied in HAVING:
//   1+4. prefix_len >= 16 — hard cap: nothing broader than /16 (65k IPs) ever emitted.
//        Eliminates coarse ASN-level blocks (/8–/15) from major telecoms and ISPs that
//        would indiscriminately block millions of legitimate IPs.
//   3.   hit density >= 0.001 — requires at least 1 observed hit per 1,000 addresses in
//        the range. For /16 this means 65+ hits; for /20 it means 4+; for /24 it means 1+.
//        Filters out ranges that appear due to random/incidental IP overlap rather than
//        genuine concentrated scanning activity.
$cidrs = [];
if ($has_data) {
    $cidr_stmt = $con->prepare(
        'SELECT cidr, asn, org,
                SUM(report_count) AS report_count,
                SUM(total_hits)   AS total_hits,
                CAST(SUBSTRING_INDEX(cidr, \'/\', -1) AS UNSIGNED) AS prefix_len
         FROM community_cidr_stats
         WHERE report_date >= ?
         GROUP BY cidr, asn, org
         HAVING report_count >= 3
            AND CAST(SUBSTRING_INDEX(cidr, \'/\', -1) AS UNSIGNED) >= 16
            AND SUM(total_hits) / POW(2, 32 - CAST(SUBSTRING_INDEX(cidr, \'/\', -1) AS UNSIGNED)) >= 0.001
         ORDER BY report_count DESC, total_hits DESC
         LIMIT 50'
    );
    $cidr_stmt->bind_param('s', $cutoff);
    $cidr_stmt->execute();
    $cidr_result = $cidr_stmt->get_result();
    while ($r = $cidr_result->fetch_assoc()) {
        $cidrs[] = $r;
    }
    $cidr_stmt->close();
}

mysqli_close($con);

// ── Serve download if ?format= is set ────────────────────────────────────────
if ($is_download && (!$has_data || empty($cidrs))) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'No community data available yet. Check back soon.';
    exit;
}

if ($is_download && $has_data && !empty($cidrs)) {
    $cidr_list = array_column($cidrs, 'cidr');
    $count     = count($cidr_list);

    if ($fmt === 'iptables') {
        $lines = array_map(fn($c) => 'iptables -A INPUT -s ' . $c . ' -j DROP', $cidr_list);
        $body = "#!/bin/bash\n"
              . "# ip2geo community block list — iptables rules\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Past 7 days from: {$cutoff} UTC\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "# Filters: 3+ corroborating reports, prefix /16 or more specific, hit density >= 0.1%\n"
              . "# REVIEW BEFORE APPLYING: ranges reflect reported attack subnets and may include\n"
              . "# infrastructure shared with legitimate services. Verify against your environment.\n"
              . "\nset -euo pipefail\n\n"
              . implode("\n", $lines) . "\n";
        $filename = "ip2geo-community-block-list-iptables-{$date_str}.sh";
        $ctype    = 'text/x-sh';
    } elseif ($fmt === 'ufw') {
        $lines = array_map(fn($c) => 'ufw deny from ' . $c . ' to any', $cidr_list);
        $body = "#!/bin/bash\n"
              . "# ip2geo community block list — ufw rules\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Past 7 days from: {$cutoff} UTC\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "# Filters: 3+ corroborating reports, prefix /16 or more specific, hit density >= 0.1%\n"
              . "# REVIEW BEFORE APPLYING: ranges reflect reported attack subnets and may include\n"
              . "# infrastructure shared with legitimate services. Verify against your environment.\n"
              . "\nset -euo pipefail\n\n"
              . implode("\n", $lines) . "\n";
        $filename = "ip2geo-community-block-list-ufw-{$date_str}.sh";
        $ctype    = 'text/x-sh';
    } elseif ($fmt === 'nginx') {
        $lines = array_map(fn($c) => $c . ' 1;', $cidr_list);
        $body = "# ip2geo community block list — nginx geo block\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Past 7 days from: {$cutoff} UTC\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "# Filters: 3+ corroborating reports, prefix /16 or more specific, hit density >= 0.1%\n"
              . "# REVIEW BEFORE APPLYING: ranges reflect reported attack subnets and may include\n"
              . "# infrastructure shared with legitimate services. Verify against your environment.\n"
              . "# Usage: include this file inside a  geo \$blocked_ip { }  block in nginx.conf\n"
              . "\ndefault 0;\n"
              . implode("\n", $lines) . "\n";
        $filename = "ip2geo-community-block-list-nginx-{$date_str}.conf";
        $ctype    = 'text/plain';
    } else { // txt
        $body = "# ip2geo community block list — CIDR ranges\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Past 7 days from: {$cutoff} UTC\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "# Filters: 3+ corroborating reports, prefix /16 or more specific, hit density >= 0.1%\n"
              . "# REVIEW BEFORE APPLYING: ranges reflect reported attack subnets and may include\n"
              . "# infrastructure shared with legitimate services. Verify against your environment.\n"
              . "# One range per line — paste into ipset, web firewall, or any blocklist tool\n"
              . implode("\n", $cidr_list) . "\n";
        $filename = "ip2geo-community-block-list-{$date_str}.txt";
        $ctype    = 'text/plain';
    }

    header('Content-Type: ' . $ctype . '; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

// ── Start output buffer for HTML page cache ───────────────────────────────────
ob_start();
require __DIR__ . '/includes/page-chrome.php';
render_page_open(
    'Community Block List — ip2geo.org',
    'Weekly community-sourced IP block list derived from opted-in ip2geo threat reports. Download CIDR ranges for iptables, ufw, nginx, or plain text.'
);
?>
<section class="report-section">
    <div class="report-inner">
        <div class="section-head">
            <h1>Community Block List</h1>
            <span class="section-tag">/ Intel</span>
        </div>
        <p class="section-subtitle">Past 7 days &mdash; updates as users contribute</p>

        <?php if (!$has_data): ?>

        <p>Not enough data yet this week. Check back soon.</p>
        <p class="report-fine-print">
            The community feed requires at least 5 opted-in threat reports for the current week.
            As more users run reports and share their data, this page will populate automatically.
        </p>

        <?php elseif (!empty($cidrs)): ?>

        <p>
            Derived from <strong><?php echo number_format($total_reports); ?></strong> opted-in
            ip2geo threat reports this week. Updated continuously.
            <a href="/privacy.php" class="link-muted">Privacy policy</a>
        </p>

        <div class="button-row">
            <a href="/intel.php?format=iptables" class="button small">&#8595; iptables</a>
            <a href="/intel.php?format=ufw"      class="button small">&#8595; ufw</a>
            <a href="/intel.php?format=nginx"    class="button small">&#8595; nginx</a>
            <a href="/intel.php?format=txt"      class="button small alt">&#8595; plain .txt</a>
        </div>

        <div class="table-wrapper table-wrapper--scroll">
        <table class="intel-table">
            <thead>
                <tr>
                    <th scope="col" class="col-mono">CIDR</th>
                    <th scope="col">ASN Org</th>
                    <th scope="col" title="Opted-in reports containing this range in the past 7 days">Reports</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($cidrs as $row):
                $cidr_slug = 'cidr-' . preg_replace('/[.\/:]+/', '-', $row['cidr']);
            ?>
                <tr id="<?php echo htmlspecialchars($cidr_slug, ENT_QUOTES, 'UTF-8'); ?>">
                    <td class="col-mono"><?php echo htmlspecialchars($row['cidr'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td><?php echo htmlspecialchars(($row['asn'] ?? '') . ($row['org'] ? ' ' . $row['org'] : ''), ENT_QUOTES, 'UTF-8'); ?></td>
                    <td><?php echo (int)$row['report_count']; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>

        <p class="report-fine-print">
            Top <?php echo count($cidrs); ?> ranges by report count.
            Included only if: reported by 3+ independent users, prefix /16 or more specific (max 65,536 addresses), and hit density &ge;0.1% of the range.
            Ranges from cloud and ISP infrastructure may still appear &mdash; review carefully before applying to production.
            Residential IPs are never collected. Data retained for 52 weeks.
        </p>

        <?php else: ?>

        <p>
            We have <strong><?php echo number_format($total_reports); ?></strong> opted-in
            ip2geo threat reports this week, but no ranges currently meet the confidence threshold.
            <a href="/privacy.php" class="link-muted">Privacy policy</a>
        </p>
        <p class="report-fine-print">
            To appear here, a CIDR must be seen in 3 or more independent reports, have a prefix of /16 or more specific
            (at most 65,536 addresses), and show a hit density of at least 0.1% of its range.
            The list will populate as more users contribute reports this week.
        </p>

        <?php endif; ?>

        <hr class="section-rule" />
        <div class="button-row">
            <a href="/report.php?token=00000000-0000-0000-0000-000000000000" class="button small alt">See a sample report &rarr;</a>
            <a href="/" class="button small alt">Analyze your own logs &rarr;</a>
        </div>
    </div>
</section>
<?php
render_page_close();

// ── Store rendered HTML in APCu (15-min TTL) ──────────────────────────────────
$_html = ob_get_clean();
if ($_html === false || $_html === '') {
    // Output buffering failed — do not cache; emit a recoverable error.
    http_response_code(500);
    echo 'Page rendering error. Please try again.';
    exit;
}
if (function_exists('apcu_store')) {
    apcu_store($_cache_key, $_html, 900);
}
echo $_html;
