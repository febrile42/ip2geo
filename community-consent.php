<?php
/**
 * Community Threat Intelligence consent endpoint.
 *
 * Called via AJAX from report.php when a user opts in or declines to
 * contribute anonymized data to the community threat feed.
 *
 * POST parameters:
 *   token   — report token (UUID)
 *   consent — '1' (opt in) or '0' (decline)
 *
 * On opt-in: sets data_consent=1, ingests CIDR + IP aggregate data
 * from the report's stored JSON into community_cidr_stats and
 * community_ip_stats. Returns community context for inline rendering.
 *
 * On decline: sets data_consent=0. Returns {"ok":true}.
 *
 * IMPORTANT: do not log token-to-IP associations anywhere in this file.
 * The anonymization guarantee depends on no linkage between the aggregate
 * rows and the contributing report being persisted anywhere, including logs.
 */

require __DIR__ . '/config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'method_not_allowed']);
    exit;
}

$token   = isset($_POST['token'])   ? trim($_POST['token'])   : '';
$consent = isset($_POST['consent']) ? (int) $_POST['consent'] : -1;

if ($token === '' || !in_array($consent, [0, 1], true)) {
    http_response_code(400);
    echo json_encode(['error' => 'bad_request']);
    exit;
}

// ── DB connection ─────────────────────────────────────────────────────────────

$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    http_response_code(500);
    echo json_encode(['error' => 'db_error']);
    exit;
}

// ── Validate token ────────────────────────────────────────────────────────────

$stmt = $con->prepare(
    'SELECT status, data_consent, report_json, ip_list_json
     FROM reports WHERE token = ?'
);
$stmt->bind_param('s', $token);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$row || !in_array($row['status'], ['paid', 'redeemed'], true)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_token']);
    mysqli_close($con);
    exit;
}

// ── Idempotency: already set ──────────────────────────────────────────────────
// Allow upgrading from declined (0) → opted-in (1); block all other repeats.

if ($row['data_consent'] !== null) {
    $upgrading = ($consent === 1 && (int)$row['data_consent'] === 0);
    if (!$upgrading) {
        echo json_encode(['ok' => true, 'already_set' => true]);
        mysqli_close($con);
        exit;
    }
}

// ── Decline: record and return ────────────────────────────────────────────────

if ($consent === 0) {
    $stmt = $con->prepare('UPDATE reports SET data_consent = 0 WHERE token = ?');
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $stmt->close();
    echo json_encode(['ok' => true]);
    mysqli_close($con);
    exit;
}

// ── Opt-in: record consent first, then ingest ─────────────────────────────────

$stmt = $con->prepare('UPDATE reports SET data_consent = 1 WHERE token = ?');
$stmt->bind_param('s', $token);
$stmt->execute();
$stmt->close();

// ── Parse stored JSON ─────────────────────────────────────────────────────────

$report   = !empty($row['report_json'])   ? json_decode($row['report_json'],   true) : null;
$ip_list  = !empty($row['ip_list_json'])  ? json_decode($row['ip_list_json'],  true) : null;

if ($report === null || $ip_list === null) {
    // Consent recorded; skip ingestion — report data unavailable or malformed.
    error_log('ip2geo community-consent.php: report/ip_list JSON missing or malformed for ingestion (token omitted)');
    echo json_encode(['ok' => true, 'ingested' => false]);
    mysqli_close($con);
    exit;
}

// ── Use today's date for rolling 7-day aggregation ───────────────────────────
$report_date = gmdate('Y-m-d');

// ── Build IP → freq map for CIDR hit counting (all IPs, all classifications) ──
// Counts all hits from the report's IP list, regardless of classification —
// the CIDR represents the network, and we want total traffic from it.
$ip_freq = [];
foreach ($ip_list as $entry) {
    $ip = $entry['ip'] ?? '';
    if ($ip !== '') {
        $ip_freq[$ip] = (int)($entry['freq'] ?? 1);
    }
}

function ip_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$network, $prefix] = explode('/', $cidr, 2);
    $prefix    = (int)$prefix;
    $ip_long   = ip2long($ip);
    $net_long  = ip2long($network);
    if ($ip_long === false || $net_long === false) return false;
    if ($prefix === 0) return true;
    $mask = ~0 << (32 - $prefix);
    return ($ip_long & $mask) === ($net_long & $mask);
}

// ── Ingest CIDR data ──────────────────────────────────────────────────────────

$asn_ranges = $report['asn_ranges'] ?? [];

if (!empty($asn_ranges)) {
    $cidr_stmt = $con->prepare(
        'INSERT INTO community_cidr_stats (cidr, asn, org, report_date, report_count, total_hits)
         VALUES (?, ?, ?, ?, 1, ?)
         ON DUPLICATE KEY UPDATE
           report_count = report_count + 1,
           total_hits   = total_hits + VALUES(total_hits)'
    );

    foreach ($asn_ranges as $range) {
        $asn = $range['asn'] ?? '';
        $org = $range['org'] ?? '';
        foreach ($range['cidrs'] ?? [] as $cidr_entry) {
            $cidr = is_array($cidr_entry) ? ($cidr_entry['cidr'] ?? '') : (string)$cidr_entry;
            if ($cidr === '' || $asn === '') continue;

            // Count total hits from report IPs that fall within this CIDR.
            $hits = 0;
            foreach ($ip_freq as $ip => $freq) {
                if (ip_in_cidr($ip, $cidr)) $hits += $freq;
            }
            if ($hits === 0) continue; // No observed hits from this report — skip

            $cidr_stmt->bind_param('ssssi', $cidr, $asn, $org, $report_date, $hits);
            $cidr_stmt->execute();
        }
    }
    $cidr_stmt->close();
}

// ── Ingest IP data (scanning/VPN/cloud only — never residential) ──────────────

$allowed_classifications = ['scanning', 'vpn_proxy', 'cloud_exit'];
$ip_stmt = $con->prepare(
    'INSERT INTO community_ip_stats (ip, report_date, report_count, total_hits)
     VALUES (?, ?, 1, ?)
     ON DUPLICATE KEY UPDATE
       report_count = report_count + 1,
       total_hits   = total_hits + VALUES(total_hits)'
);
$fs_stmt = $con->prepare(
    'INSERT IGNORE INTO community_ip_first_seen (ip, first_seen) VALUES (?, ?)'
);

foreach ($ip_list as $entry) {
    $classification = $entry['classification'] ?? '';
    if (!in_array($classification, $allowed_classifications, true)) {
        continue; // residential and unknown: skip
    }
    $ip   = $entry['ip']   ?? '';
    $hits = (int) ($entry['freq'] ?? 1);
    if ($ip === '') continue;

    $ip_stmt->bind_param('ssi', $ip, $report_date, $hits);
    $ip_stmt->execute();

    $fs_stmt->bind_param('ss', $ip, $report_date);
    $fs_stmt->execute();
}
$ip_stmt->close();
$fs_stmt->close();

// ── Increment daily opted-in report counter ───────────────────────────────────
$wk_stmt = $con->prepare(
    'INSERT INTO community_weekly_stats (report_date, opted_in_reports)
     VALUES (?, 1) ON DUPLICATE KEY UPDATE opted_in_reports = opted_in_reports + 1'
);
$wk_stmt->bind_param('s', $report_date);
$wk_stmt->execute();
$wk_stmt->close();

// ── Build community context for inline render ─────────────────────────────────
// Return top CIDR counts for this week so report.php can render the callout
// without a page reload.

$_ctx_cutoff = gmdate('Y-m-d', strtotime('-7 days'));
$ctx_stmt = $con->prepare(
    'SELECT cidr, asn, org, SUM(report_count) AS report_count, SUM(total_hits) AS total_hits
     FROM community_cidr_stats
     WHERE report_date >= ?
     GROUP BY cidr, asn, org
     HAVING report_count >= 3
        AND CAST(SUBSTRING_INDEX(cidr, \'/\', -1) AS UNSIGNED) >= 16
        AND SUM(total_hits) / POW(2, 32 - CAST(SUBSTRING_INDEX(cidr, \'/\', -1) AS UNSIGNED)) >= 0.001
     ORDER BY report_count DESC, total_hits DESC
     LIMIT 5'
);
$ctx_stmt->bind_param('s', $_ctx_cutoff);
$ctx_stmt->execute();
$top_cidrs = $ctx_stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$ctx_stmt->close();

mysqli_close($con);

echo json_encode([
    'ok'        => true,
    'ingested'  => true,
    'top_cidrs' => $top_cidrs,
]);
