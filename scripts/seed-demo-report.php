#!/usr/bin/env php
<?php
/**
 * Seed the public demo report.
 *
 * Uses known Tor exit nodes and scanning infrastructure that have
 * real AbuseIPDB community reports. Run once (or to refresh the demo):
 *
 *   php scripts/seed-demo-report.php
 *
 * The demo token is a fixed UUID stored as DEMO_TOKEN below.
 * report.php checks for it and shows a DEMO banner instead of expiry info.
 */

define('DEMO_TOKEN', '00000000-0000-0000-0000-000000000000');

$root = dirname(__DIR__);
require $root . '/config.php';
require $root . '/asn_classification.php';
require $root . '/report_functions.php';

// ── IP list ───────────────────────────────────────────────────────────────────
// Tor exits from Zwiebelfreunde e.V. (AS204900, 185.220.101.x) and
// Freiheitsfoo (AS205100, 185.220.102.x): well-documented, community-reported,
// score 75–100 on AbuseIPDB.  Mixed with cloud egress and a few residential IPs
// to give a realistic-looking incident log.
//
// freq > 1 = IP appeared multiple times in the simulated log (SSH brute-force
// scenario where repeat offenders hammer the same port).

$raw = [
    // Tor exits — freq 3–12 (simulates a burst of repeated attempts)
    ['ip' => '185.220.101.1',  'freq' => 12, 'label' => 'tor'],
    ['ip' => '185.220.101.2',  'freq' => 10, 'label' => 'tor'],
    ['ip' => '185.220.101.3',  'freq' => 9,  'label' => 'tor'],
    ['ip' => '185.220.101.4',  'freq' => 8,  'label' => 'tor'],
    ['ip' => '185.220.101.5',  'freq' => 8,  'label' => 'tor'],
    ['ip' => '185.220.101.6',  'freq' => 7,  'label' => 'tor'],
    ['ip' => '185.220.101.7',  'freq' => 7,  'label' => 'tor'],
    ['ip' => '185.220.101.8',  'freq' => 6,  'label' => 'tor'],
    ['ip' => '185.220.101.9',  'freq' => 6,  'label' => 'tor'],
    ['ip' => '185.220.101.10', 'freq' => 5,  'label' => 'tor'],
    ['ip' => '185.220.101.11', 'freq' => 5,  'label' => 'tor'],
    ['ip' => '185.220.101.12', 'freq' => 4,  'label' => 'tor'],
    ['ip' => '185.220.101.13', 'freq' => 4,  'label' => 'tor'],
    ['ip' => '185.220.101.14', 'freq' => 4,  'label' => 'tor'],
    ['ip' => '185.220.101.15', 'freq' => 3,  'label' => 'tor'],
    ['ip' => '185.220.101.16', 'freq' => 3,  'label' => 'tor'],
    ['ip' => '185.220.101.17', 'freq' => 3,  'label' => 'tor'],
    ['ip' => '185.220.101.18', 'freq' => 3,  'label' => 'tor'],
    ['ip' => '185.220.101.19', 'freq' => 2,  'label' => 'tor'],
    ['ip' => '185.220.101.20', 'freq' => 2,  'label' => 'tor'],
    ['ip' => '185.220.101.21', 'freq' => 2,  'label' => 'tor'],
    ['ip' => '185.220.101.22', 'freq' => 2,  'label' => 'tor'],
    ['ip' => '185.220.101.23', 'freq' => 2,  'label' => 'tor'],
    ['ip' => '185.220.101.24', 'freq' => 1,  'label' => 'tor'],
    ['ip' => '185.220.101.25', 'freq' => 1,  'label' => 'tor'],
    // More Tor exits — freq 1–2 (single-hit scanners in the log tail)
    ['ip' => '185.220.100.240', 'freq' => 2, 'label' => 'tor'],
    ['ip' => '185.220.100.241', 'freq' => 2, 'label' => 'tor'],
    ['ip' => '185.220.100.242', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.243', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.244', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.245', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.246', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.247', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.248', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.249', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.250', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.251', 'freq' => 1, 'label' => 'tor'],
    ['ip' => '185.220.100.252', 'freq' => 1, 'label' => 'tor'],
    // Cloud exit IPs (AWS/GCP ranges — common in real incident logs)
    ['ip' => '34.105.0.1',  'freq' => 1, 'label' => 'cloud'],
    ['ip' => '34.105.0.2',  'freq' => 1, 'label' => 'cloud'],
    ['ip' => '34.105.0.3',  'freq' => 1, 'label' => 'cloud'],
    ['ip' => '52.14.0.1',   'freq' => 1, 'label' => 'cloud'],
    ['ip' => '52.14.0.2',   'freq' => 1, 'label' => 'cloud'],
    ['ip' => '52.14.0.3',   'freq' => 1, 'label' => 'cloud'],
    ['ip' => '52.14.0.4',   'freq' => 1, 'label' => 'cloud'],
    ['ip' => '52.14.0.5',   'freq' => 1, 'label' => 'cloud'],
    // Residential — noise in the log (low freq, no threat signal)
    ['ip' => '8.8.8.8',     'freq' => 1, 'label' => 'residential'],
    ['ip' => '8.8.4.4',     'freq' => 1, 'label' => 'residential'],
    ['ip' => '1.1.1.1',     'freq' => 1, 'label' => 'residential'],
    ['ip' => '9.9.9.9',     'freq' => 1, 'label' => 'residential'],
    ['ip' => '208.67.222.222', 'freq' => 1, 'label' => 'residential'],
];

$all_ips = array_column($raw, 'ip');

// ── DB connection ─────────────────────────────────────────────────────────────
$con = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (mysqli_connect_errno()) {
    die('DB connect failed: ' . mysqli_connect_error() . "\n");
}

function ipToLong(string $ip): string {
    return sprintf('%u', ip2long($ip));
}

// ── Geo lookups ───────────────────────────────────────────────────────────────
echo "Running geo lookups for " . count($all_ips) . " IPs...\n";
$ip_data = [];
foreach ($all_ips as $ip) {
    $ip_int = ipToLong($ip);
    $query = 'SELECT loc.country_iso_code, loc.country_name,
                     asn_net.autonomous_system_number, asn_net.autonomous_system_org
              FROM (
                  SELECT geoname_id, network_end_integer
                  FROM geoip2_network_current_int
                  WHERE ' . $ip_int . ' >= network_start_integer
                  ORDER BY network_start_integer DESC LIMIT 1
              ) city_net
              LEFT JOIN geoip2_location_current loc
                  ON (city_net.geoname_id = loc.geoname_id AND loc.locale_code = "en")
              LEFT JOIN (
                  SELECT autonomous_system_number, autonomous_system_org
                  FROM geoip2_asn_current_int
                  WHERE ' . $ip_int . ' >= network_start_integer
                  ORDER BY network_start_integer DESC LIMIT 1
              ) asn_net ON 1=1
              WHERE ' . $ip_int . ' <= city_net.network_end_integer';

    $result = mysqli_query($con, $query);
    $row = mysqli_fetch_assoc($result);

    $raw_freq = 1;
    foreach ($raw as $entry) {
        if ($entry['ip'] === $ip) { $raw_freq = $entry['freq']; break; }
    }

    if ($row) {
        $asn_num = $row['autonomous_system_number'] ?? '';
        $asn_org = $row['autonomous_system_org'] ?? '';
        $cat = classify_asn((string)$asn_num, (string)$asn_org);
        $ip_data[] = [
            'ip'             => $ip,
            'asn'            => $asn_num !== '' ? 'AS' . $asn_num : '',
            'asn_org'        => $asn_org,
            'classification' => $cat,
            'country'        => $row['country_iso_code'] ?? '',
            'freq'           => $raw_freq,
        ];
        echo "  $ip → $cat (" . ($asn_num ? 'AS'.$asn_num : 'no ASN') . ")\n";
    } else {
        // Include even if no geo hit — use label as classification hint
        $raw_entry = current(array_filter($raw, fn($e) => $e['ip'] === $ip));
        $fallback_cat = match($raw_entry['label'] ?? '') {
            'tor'   => 'scanning',
            'cloud' => 'cloud',
            default => 'unknown',
        };
        $ip_data[] = [
            'ip'             => $ip,
            'asn'            => '',
            'asn_org'        => '',
            'classification' => $fallback_cat,
            'country'        => '',
            'freq'           => $raw_freq,
        ];
        echo "  $ip → no geo (fallback: $fallback_cat)\n";
    }
}

// ── Build report data ─────────────────────────────────────────────────────────
$total = count($ip_data);
$cat_counts = ['scanning' => 0, 'cloud' => 0, 'vpn' => 0, 'residential' => 0, 'unknown' => 0];
$country_counts = [];
foreach ($ip_data as $entry) {
    $cat = $entry['classification'];
    $cat_counts[$cat] = ($cat_counts[$cat] ?? 0) + 1;
    $cc = $entry['country'];
    if ($cc !== '') $country_counts[$cc] = ($country_counts[$cc] ?? 0) + 1;
}
$scanning_proxy = $cat_counts['scanning'] + $cat_counts['vpn'];
$scanning_pct   = $total > 0 ? $scanning_proxy / $total : 0;

$verdict = compute_verdict($scanning_proxy, $total);
$top25   = rank_ips($ip_data, 25);

echo "\nVerdict: $verdict ($scanning_proxy/$total scanning+vpn = " . round($scanning_pct * 100) . "%)\n";
echo "Running AbuseIPDB lookups for top " . count($top25) . " IPs...\n";

// ── AbuseIPDB enrichment ──────────────────────────────────────────────────────
$api_key = $abuseipdb_api_key ?? '';
if ($api_key === '') {
    echo "WARNING: no abuseipdb_api_key in config — scores will be null\n";
    foreach ($top25 as &$e) $e['abuse_score'] = null;
    unset($e);
} else {
    $multi   = curl_multi_init();
    $handles = [];
    foreach ($top25 as $entry) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => 'https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode($entry['ip']) . '&maxAgeInDays=90',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_HTTPHEADER     => ['Key: ' . $api_key, 'Accept: application/json'],
        ]);
        curl_multi_add_handle($multi, $ch);
        $handles[$entry['ip']] = $ch;
    }
    $running = null;
    do { curl_multi_exec($multi, $running); curl_multi_select($multi); } while ($running > 0);

    $scores = [];
    foreach ($handles as $ip => $ch) {
        $body = curl_multi_getcontent($ch);
        $data = json_decode($body, true);
        $score = (int)($data['data']['abuseConfidenceScore'] ?? 0);
        $reports = (int)($data['data']['totalReports'] ?? 0);
        $scores[$ip] = ['score' => $score, 'reports' => $reports];
        $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        echo "  $ip → score=$score, reports=$reports (HTTP $http)\n";
        curl_multi_remove_handle($multi, $ch);
        curl_close($ch);
    }
    curl_multi_close($multi);

    foreach ($top25 as &$entry) {
        $entry['abuse_score']        = $scores[$entry['ip']]['score'] ?? null;
        $entry['abuse_total_reports'] = $scores[$entry['ip']]['reports'] ?? null;
    }
    unset($entry);

    // Cache scores so they appear in view_token mode too
    $today = date('Y-m-d');
    foreach ($scores as $ip => $s) {
        $stmt = $con->prepare(
            'INSERT INTO abuseipdb_cache (ip, confidence_score, total_reports, queried_at)
             VALUES (?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
               confidence_score = VALUES(confidence_score),
               total_reports    = VALUES(total_reports),
               queried_at       = NOW()'
        );
        $stmt->bind_param('sii', $ip, $s['score'], $s['reports']);
        $stmt->execute();
        $stmt->close();
    }
    $actual = count($scores);
    $con->query("INSERT INTO abuseipdb_daily_usage (usage_date, calls_made) VALUES ('$today', $actual)
                 ON DUPLICATE KEY UPDATE calls_made = calls_made + $actual");
}

$verdict = maybe_upgrade_verdict($verdict, $top25);
echo "Final verdict (post-AbuseIPDB upgrade): $verdict\n";

arsort($country_counts);
$top_countries = array_slice($country_counts, 0, 5, true);

// block_ips: all scanning/VPN IPs sorted by freq desc
$block_entries = array_values(array_filter($ip_data, fn($e) => in_array($e['classification'], ['scanning', 'vpn'], true)));
usort($block_entries, fn($a, $b) => ($b['freq'] ?? 1) <=> ($a['freq'] ?? 1));
$block_ips = array_column($block_entries, 'ip');

$report = [
    'verdict'        => $verdict,
    'total_ips'      => $total,
    'scanning_pct'   => round($scanning_pct * 100),
    'scanning_count' => $scanning_proxy,
    'cat_counts'     => $cat_counts,
    'top_countries'  => $top_countries,
    'top25'          => $top25,
    'block_ips'      => $block_ips,
    'generated_at'   => date('Y-m-d H:i:s'),
    'abuseipdb_note' => null,
];

// ip_list_json: same as ip_data but without asn_org (matches what index.php stores)
$ip_list_json = array_map(fn($e) => [
    'ip'             => $e['ip'],
    'asn'            => $e['asn'],
    'classification' => $e['classification'],
    'country'        => $e['country'],
    'freq'           => $e['freq'],
], $ip_data);

// ── Upsert demo row ───────────────────────────────────────────────────────────
$token          = DEMO_TOKEN;
$report_json    = json_encode($report);
$ip_list_json_s = json_encode($ip_list_json);
$hash           = 'demo';

$stmt = $con->prepare(
    'INSERT INTO reports (token, submission_hash, ip_list_json, status, report_json,
                          report_expires_at, pending_expires_at)
     VALUES (?, ?, ?, "redeemed", ?, NULL, NOW())
     ON DUPLICATE KEY UPDATE
       ip_list_json      = VALUES(ip_list_json),
       status            = "redeemed",
       report_json       = VALUES(report_json),
       report_expires_at = NULL'
);
$stmt->bind_param('ssss', $token, $hash, $ip_list_json_s, $report_json);
$stmt->execute();
$stmt->close();

mysqli_close($con);

echo "\nDemo report seeded.\n";
echo "Token: " . DEMO_TOKEN . "\n";
echo "URL: /report.php?token=" . DEMO_TOKEN . "\n";
echo "View all IPs: /?view_token=" . DEMO_TOKEN . "\n";
