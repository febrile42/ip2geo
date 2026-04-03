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

if ($row['data_consent'] !== null) {
    echo json_encode(['ok' => true, 'already_set' => true]);
    mysqli_close($con);
    exit;
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

// ── Compute week_start (Monday of current ISO week, UTC) ──────────────────────
// PHP's 'N' format = ISO day of week: 1=Mon … 7=Sun
$days_since_monday = (int) gmdate('N') - 1;
$week_start = gmdate('Y-m-d', strtotime("-{$days_since_monday} days"));

// ── Ingest CIDR data ──────────────────────────────────────────────────────────

$asn_ranges = $report['asn_ranges'] ?? [];

if (!empty($asn_ranges)) {
    $cidr_stmt = $con->prepare(
        'INSERT INTO community_cidr_stats (cidr, asn, org, week_start, report_count, total_hits)
         VALUES (?, ?, ?, ?, 1, ?)
         ON DUPLICATE KEY UPDATE
           report_count = report_count + 1,
           total_hits   = total_hits + VALUES(total_hits)'
    );

    foreach ($asn_ranges as $range) {
        $asn = $range['asn'] ?? '';
        $org = $range['org'] ?? '';
        foreach ($range['cidrs'] ?? [] as $cidr_entry) {
            // cidr_entry may be a string or ['cidr'=>..., 'hits'=>...]
            if (is_array($cidr_entry)) {
                $cidr = $cidr_entry['cidr'] ?? '';
                $hits = (int) ($cidr_entry['hits'] ?? 1);
            } else {
                $cidr = (string) $cidr_entry;
                $hits = 1;
            }
            if ($cidr === '' || $asn === '') continue;
            $cidr_stmt->bind_param('ssssi', $cidr, $asn, $org, $week_start, $hits);
            $cidr_stmt->execute();
        }
    }
    $cidr_stmt->close();
}

// ── Ingest IP data (scanning/VPN/cloud only — never residential) ──────────────

$allowed_classifications = ['scanning', 'vpn_proxy', 'cloud_exit'];
$ip_stmt = $con->prepare(
    'INSERT INTO community_ip_stats (ip, week_start, report_count, total_hits)
     VALUES (?, ?, 1, ?)
     ON DUPLICATE KEY UPDATE
       report_count = report_count + 1,
       total_hits   = total_hits + VALUES(total_hits)'
);
$fs_stmt = $con->prepare(
    'INSERT IGNORE INTO community_ip_first_seen (ip, first_seen) VALUES (?, ?)'
);

$today = gmdate('Y-m-d');

foreach ($ip_list as $entry) {
    $classification = $entry['classification'] ?? '';
    if (!in_array($classification, $allowed_classifications, true)) {
        continue; // residential and unknown: skip
    }
    $ip   = $entry['ip']   ?? '';
    $hits = (int) ($entry['freq'] ?? 1);
    if ($ip === '') continue;

    $ip_stmt->bind_param('ssi', $ip, $week_start, $hits);
    $ip_stmt->execute();

    $fs_stmt->bind_param('ss', $ip, $today);
    $fs_stmt->execute();
}
$ip_stmt->close();
$fs_stmt->close();

// ── Build community context for inline render ─────────────────────────────────
// Return top CIDR counts for this week so report.php can render the callout
// without a page reload.

$ctx_stmt = $con->prepare(
    'SELECT cidr, org, report_count, total_hits
     FROM community_cidr_stats
     WHERE week_start = ?
     ORDER BY report_count DESC, total_hits DESC
     LIMIT 5'
);
$ctx_stmt->bind_param('s', $week_start);
$ctx_stmt->execute();
$top_cidrs = $ctx_stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$ctx_stmt->close();

mysqli_close($con);

echo json_encode([
    'ok'        => true,
    'ingested'  => true,
    'week_start' => $week_start,
    'top_cidrs' => $top_cidrs,
]);
