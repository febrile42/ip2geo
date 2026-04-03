<?php
/**
 * Community Block List — /intel.php
 *
 * Public page showing the top CIDR ranges reported by opted-in ip2geo users
 * this week. Data sourced from community_cidr_stats (via community-consent.php).
 *
 * Minimum threshold: 5 report_count rows for current week before data is shown.
 * Download formats: iptables / ufw / nginx / plain .txt (top 50 CIDRs).
 * No auth required. Updated continuously as users opt in.
 */

require __DIR__ . '/config.php';

header('X-Content-Type-Options: nosniff');

// ── Compute week_start (Monday of current ISO week, UTC) ──────────────────────
$days_since_monday = (int) gmdate('N') - 1;
$week_start = gmdate('Y-m-d', strtotime("-{$days_since_monday} days"));
$week_label = date('F j, Y', strtotime($week_start));

// ── DB connection ─────────────────────────────────────────────────────────────
$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    http_response_code(503);
    echo 'Database unavailable. Please try again shortly.';
    exit;
}

// ── Check threshold (min 5 opted-in reports this week) ───────────────────────
$thr_stmt = $con->prepare(
    'SELECT COALESCE(SUM(report_count), 0) AS total_reports
     FROM community_cidr_stats WHERE week_start = ?'
);
$thr_stmt->bind_param('s', $week_start);
$thr_stmt->execute();
$thr_row = $thr_stmt->get_result()->fetch_assoc();
$thr_stmt->close();

$total_reports = (int)($thr_row['total_reports'] ?? 0);
$has_data = $total_reports >= 5;

// ── Fetch top 50 CIDRs ────────────────────────────────────────────────────────
$cidrs = [];
if ($has_data) {
    $cidr_stmt = $con->prepare(
        'SELECT cidr, asn, org, report_count, total_hits
         FROM community_cidr_stats
         WHERE week_start = ?
         ORDER BY report_count DESC, total_hits DESC
         LIMIT 50'
    );
    $cidr_stmt->bind_param('s', $week_start);
    $cidr_stmt->execute();
    $cidr_result = $cidr_stmt->get_result();
    while ($r = $cidr_result->fetch_assoc()) {
        $cidrs[] = $r;
    }
    $cidr_stmt->close();
}

mysqli_close($con);

// ── Serve download if ?format= is set ────────────────────────────────────────
$fmt = isset($_GET['format']) ? $_GET['format'] : '';
$valid_formats = ['iptables', 'ufw', 'nginx', 'txt'];

if ($fmt !== '' && in_array($fmt, $valid_formats, true) && $has_data && !empty($cidrs)) {
    $cidr_list = array_column($cidrs, 'cidr');
    $date_str  = gmdate('Y-m-d');
    $count     = count($cidr_list);

    if ($fmt === 'iptables') {
        $lines = array_map(fn($c) => 'iptables -A INPUT -s ' . $c . ' -j DROP', $cidr_list);
        $body = "#!/bin/bash\n"
              . "# ip2geo community block list — iptables rules\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Week of: {$week_start}\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "\nset -euo pipefail\n\n"
              . implode("\n", $lines) . "\n";
        $filename = 'community-block-iptables.sh';
        $ctype    = 'text/x-sh';
    } elseif ($fmt === 'ufw') {
        $lines = array_map(fn($c) => 'ufw deny from ' . $c . ' to any', $cidr_list);
        $body = "#!/bin/bash\n"
              . "# ip2geo community block list — ufw rules\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Week of: {$week_start}\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "\nset -euo pipefail\n\n"
              . implode("\n", $lines) . "\n";
        $filename = 'community-block-ufw.sh';
        $ctype    = 'text/x-sh';
    } elseif ($fmt === 'nginx') {
        $lines = array_map(fn($c) => $c . ' 1;', $cidr_list);
        $body = "# ip2geo community block list — nginx geo block\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Week of: {$week_start}\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "# Usage: include this file inside a  geo \$blocked_ip { }  block in nginx.conf\n"
              . "\ndefault 0;\n"
              . implode("\n", $lines) . "\n";
        $filename = 'community-block-nginx.conf';
        $ctype    = 'text/plain';
    } else { // txt
        $body = "# ip2geo community block list — CIDR ranges\n"
              . "# Generated: {$date_str} UTC\n"
              . "# Week of: {$week_start}\n"
              . "# Source: ip2geo.org/intel.php\n"
              . "# {$count} CIDR ranges derived from {$total_reports} opted-in threat reports\n"
              . "# One range per line — paste into ipset, web firewall, or any blocklist tool\n"
              . implode("\n", $cidr_list) . "\n";
        $filename = 'community-cidrs.txt';
        $ctype    = 'text/plain';
    }

    header('Content-Type: ' . $ctype . '; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}
?>
<!DOCTYPE HTML>
<!--
    Hyperspace by HTML5 UP
    html5up.net | @ajlkn
    Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html lang="en">
    <head>
        <!-- Umami (production only) -->
        <?php if ($_SERVER['HTTP_HOST'] === 'ip2geo.org'): ?>
        <script defer src="https://cloud.umami.is/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e"></script>
        <?php endif; ?>
        <title>Community Block List &mdash; ip2geo.org</title>
        <meta charset="utf-8" />
        <meta name="description" content="Weekly community-sourced IP block list derived from opted-in ip2geo threat reports. Download CIDR ranges for iptables, ufw, nginx, or plain text." />
        <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
        <link rel="stylesheet" href="assets/css/main.css" />
        <link rel="icon" href="/favicon.ico" />
        <noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
    </head>
    <body class="is-preload">

        <!-- Header -->
        <header id="header">
            <a href="/" class="title">ip2geo.org</a>
            <nav>
                <ul>
                    <li><a href="/">Home</a></li>
                </ul>
            </nav>
        </header>

        <!-- Wrapper -->
        <div id="wrapper">

            <!-- Main -->
            <section id="main" class="wrapper">
                <div class="inner">
                    <h1 class="major">Community Block List</h1>
                    <p style="opacity:0.7;margin-top:-0.5em">Week of <?php echo htmlspecialchars($week_label, ENT_QUOTES, 'UTF-8'); ?></p>

                    <?php if (!$has_data): ?>

                    <p>Not enough data yet this week &mdash; check back soon.</p>
                    <p style="opacity:0.7;font-size:0.9em">
                        The community feed requires at least 5 opted-in threat reports for the current week.
                        As more users run reports and share their data, this page will populate automatically.
                    </p>

                    <?php else: ?>

                    <p>
                        Derived from <strong><?php echo number_format($total_reports); ?></strong> opted-in
                        ip2geo threat reports this week. Updated continuously.
                        <a href="/privacy.php" style="opacity:0.7;font-size:0.9em">Privacy policy</a>
                    </p>

                    <div style="display:flex;gap:0.6em;flex-wrap:wrap;margin-bottom:1.5em">
                        <a href="/intel.php?format=iptables" class="button small">&#8595; iptables</a>
                        <a href="/intel.php?format=ufw"      class="button small">&#8595; ufw</a>
                        <a href="/intel.php?format=nginx"    class="button small">&#8595; nginx</a>
                        <a href="/intel.php?format=txt"      class="button small alt">&#8595; plain .txt</a>
                    </div>

                    <div class="table-wrapper" style="overflow-x:auto">
                    <table>
                        <thead>
                            <tr>
                                <th scope="col" style="font-family:monospace">CIDR</th>
                                <th scope="col">ASN Org</th>
                                <th scope="col" title="Opted-in reports containing this range this week">Reports</th>
                                <th scope="col" title="Sum of hit counts across reports">Hits</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($cidrs as $row):
                            $cidr_slug = 'cidr-' . preg_replace('/[.\/:]+/', '-', $row['cidr']);
                        ?>
                            <tr id="<?php echo htmlspecialchars($cidr_slug, ENT_QUOTES, 'UTF-8'); ?>">
                                <td style="font-family:monospace"><?php echo htmlspecialchars($row['cidr'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars(($row['asn'] ?? '') . ($row['org'] ? ' ' . $row['org'] : ''), ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo (int)$row['report_count']; ?></td>
                                <td><?php echo number_format((int)$row['total_hits']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>

                    <p style="font-size:0.8em;opacity:0.6;margin-top:0.5em">
                        Top <?php echo count($cidrs); ?> ranges by report count. Hits = sum of occurrences across all contributing reports.
                        Residential IPs are never collected. Data retained for 52 weeks.
                    </p>

                    <?php endif; ?>

                    <hr />
                    <p>
                        <a href="/report.php?token=00000000-0000-0000-0000-000000000000" class="button small alt">See a sample report &rarr;</a>
                        &nbsp;
                        <a href="/" class="button small alt">Analyze your own logs &rarr;</a>
                    </p>
                </div>
            </section>

        </div>

    <?php require __DIR__ . '/includes/footer.php'; ?>

        <!-- Scripts -->
        <script src="assets/js/jquery.min.js"></script>
        <script src="assets/js/jquery.scrollex.min.js"></script>
        <script src="assets/js/jquery.scrolly.min.js"></script>
        <script src="assets/js/browser.min.js"></script>
        <script src="assets/js/breakpoints.min.js"></script>
        <script src="assets/js/util.js"></script>
        <script src="assets/js/main.js"></script>

    </body>
</html>
