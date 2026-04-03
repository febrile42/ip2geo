<?php
/**
 * Shared pure functions used by report.php and the test suite.
 *
 * Keeping these here (not embedded inline) makes them unit-testable
 * without booting the full page or a DB connection.
 */

/**
 * Compute the threat verdict from scanning/proxy counts.
 *
 * HIGH:     ≥250 scanning abs  OR  (≥60% AND ≥20 abs)  OR  ≥80%
 * LOW:      <10 scanning abs  OR  (<5% AND <25 abs)  — unless cloud floor applies
 * MODERATE: everything else; also LOW→MODERATE when cloud heavy (≥50 abs or ≥15%)
 *
 * @param int $scanning_proxy  Number of IPs classified scanning or vpn
 * @param int $total           Total IP count (denominator)
 * @param int $cloud_count     Number of IPs classified cloud (for LOW→MODERATE floor)
 * @return string  'HIGH' | 'MODERATE' | 'LOW'
 */
function compute_verdict(int $scanning_proxy, int $total, int $cloud_count = 0): string {
    if ($total === 0) return 'LOW';

    $pct = $scanning_proxy / $total;

    if ($scanning_proxy >= 250
        || ($pct >= 0.60 && $scanning_proxy >= 20)
        || $pct >= 0.80
    ) {
        return 'HIGH';
    }

    if ($scanning_proxy < 10
        || ($pct < 0.05 && $scanning_proxy < 25)
    ) {
        // Cloud floor: heavy cloud traffic warrants MODERATE even with few scanners
        $cloud_pct = $cloud_count / $total;
        if ($cloud_count >= 50 || $cloud_pct >= 0.15) {
            return 'MODERATE';
        }
        return 'LOW';
    }

    return 'MODERATE';
}

/**
 * Upgrade a verdict one level if any top-5 AbuseIPDB score exceeds 80.
 *
 * @param string $verdict      Current verdict
 * @param array  $top25        Ranked IP entries (each may have 'abuse_score')
 * @return string              Upgraded verdict, or original if no upgrade applies
 */
function maybe_upgrade_verdict(string $verdict, array $top25): string {
    $top5_max = 0;
    foreach (array_slice($top25, 0, 5) as $entry) {
        $top5_max = max($top5_max, $entry['abuse_score'] ?? 0);
    }

    if ($top5_max > 80) {
        if ($verdict === 'MODERATE') return 'HIGH';
        if ($verdict === 'LOW')      return 'MODERATE';
    }

    return $verdict;
}

/**
 * Convert an integer start/end pair from geoip2_asn_current_int to CIDR notation.
 * The table uses INT UNSIGNED (IPv4 only), so long2ip() is always safe.
 */
function int_range_to_cidr(int $start, int $end): string {
    $size = $end - $start + 1;
    $host_bits = $size > 0 ? (int)log($size, 2) : 0;
    return long2ip($start) . '/' . (32 - $host_bits);
}

/**
 * For each unique scanning/VPN ASN in $top25, fetch its CIDR prefixes from the DB.
 * Returns up to 10 ranges per ASN, ordered largest-first.
 *
 * Requires an open mysqli $con connected to the ip2geo database.
 *
 * @return array  [ ['asn'=>'AS16276','org'=>'OVH SAS','cidrs'=>[...],'total'=>N], ... ]
 */
function fetch_asn_ranges($con, array $top25): array {
    $asn_nums = [];
    foreach ($top25 as $entry) {
        if (!in_array($entry['classification'] ?? '', ['scanning', 'vpn'], true)) continue;
        $raw = preg_replace('/^AS/i', '', trim($entry['asn'] ?? ''));
        if ($raw === '' || !ctype_digit($raw)) continue;
        $asn_nums[(int)$raw] = true;
    }

    if (empty($asn_nums)) return [];

    $nums         = array_keys($asn_nums);
    $placeholders = implode(',', array_fill(0, count($nums), '?'));
    $types        = str_repeat('i', count($nums));

    $stmt = $con->prepare(
        'SELECT autonomous_system_number, autonomous_system_org,
                network_start_integer, network_end_integer
         FROM geoip2_asn_current_int
         WHERE autonomous_system_number IN (' . $placeholders . ')
         ORDER BY autonomous_system_number,
                  (network_end_integer - network_start_integer) DESC'
    );
    $stmt->bind_param($types, ...$nums);
    $stmt->execute();
    $res = $stmt->get_result();

    $by_asn = [];
    while ($r = $res->fetch_assoc()) {
        $num = (int)$r['autonomous_system_number'];
        if (!isset($by_asn[$num])) {
            $by_asn[$num] = ['org' => $r['autonomous_system_org'] ?? '', 'cidrs' => []];
        }
        $by_asn[$num]['cidrs'][] = int_range_to_cidr(
            (int)$r['network_start_integer'],
            (int)$r['network_end_integer']
        );
    }
    $stmt->close();

    $result = [];
    foreach ($nums as $num) {
        if (!isset($by_asn[$num])) continue;
        $all   = $by_asn[$num]['cidrs'];
        $total = count($all);
        $result[] = [
            'asn'   => 'AS' . $num,
            'org'   => $by_asn[$num]['org'],
            'cidrs' => array_slice($all, 0, 10),
            'total' => $total,
        ];
    }

    return $result;
}

/**
 * Rank IP entries by threat weight: freq × (2 if scanning/vpn, else 1).
 *
 * @param array $ip_data  Array of entries with keys: ip, classification, freq
 * @param int   $limit    How many top entries to return (default 25)
 * @return array
 */
function rank_ips(array $ip_data, int $limit = 25): array {
    usort($ip_data, function (array $a, array $b): int {
        $threat = ['scanning', 'vpn'];
        $wa = in_array($a['classification'] ?? '', $threat, true) ? 2 : 1;
        $wb = in_array($b['classification'] ?? '', $threat, true) ? 2 : 1;
        $sa = ($a['freq'] ?? 1) * $wa;
        $sb = ($b['freq'] ?? 1) * $wb;
        return $sb <=> $sa;
    });

    return array_slice($ip_data, 0, $limit);
}

/**
 * Generate a rule-based threat narrative paragraph for the paid report.
 *
 * Returns an HTML-safe string suitable for direct echo inside a <p> tag.
 * ASN org names are htmlspecialchars-escaped internally.
 *
 * @param string      $verdict     'HIGH' | 'MODERATE' | 'LOW'
 * @param array       $asn_ranges  From fetch_asn_ranges(). Each entry: ['asn'=>'AS16276','org'=>'OVH SAS','cidrs'=>[...],'total'=>N]
 * @param int         $scan_pct    Percentage of IPs classified scanning/VPN (0-100). 0 used as fallback for null legacy rows.
 * @param string|null $ai_narrative Pre-escaped HTML string from Phase B Claude API, or null to use rule-based templates.
 * @return string HTML-safe string, or '' if total IPs is 0.
 */
function generate_threat_narrative(string $verdict, array $asn_ranges, int $scan_pct, ?string $ai_narrative = null): string
{
    // Phase B override: if AI narrative provided, use it directly (caller must ensure it's HTML-safe)
    if ($ai_narrative !== null) {
        return $ai_narrative;
    }

    $asn_count = count($asn_ranges);

    // Escape ASN names for HTML output
    $org0 = $asn_count >= 1 ? htmlspecialchars($asn_ranges[0]['org'] ?? '', ENT_QUOTES, 'UTF-8') : '';
    $asn0 = $asn_count >= 1 ? htmlspecialchars($asn_ranges[0]['asn'] ?? '', ENT_QUOTES, 'UTF-8') : '';
    $org1 = $asn_count >= 2 ? htmlspecialchars($asn_ranges[1]['org'] ?? '', ENT_QUOTES, 'UTF-8') : '';
    $asn1 = $asn_count >= 2 ? htmlspecialchars($asn_ranges[1]['asn'] ?? '', ENT_QUOTES, 'UTF-8') : '';

    // scan_pct fallback for legacy rows where scanning_pct was not stored
    $pct_str = $scan_pct > 0 ? "{$scan_pct}% of IPs" : "a significant portion";

    if ($verdict === 'HIGH') {
        if ($asn_count === 0) {
            return "This traffic shows a high concentration of scanning infrastructure ({$pct_str}). No ASN ranges were found — use the IP-based block scripts below.";
        } elseif ($asn_count === 1) {
            return "This traffic is a coordinated scan originating from {$org0} ({$asn0}), which accounts for the majority of your scanning hits. The CIDR ranges below cover this network permanently — blocking them stops the rotation.";
        } else {
            return "This traffic matches a coordinated port scan originating from {$org0} ({$asn0}) and {$org1} ({$asn1}) infrastructure. {$pct_str} are from known scanning infrastructure. The CIDR ranges below cover these networks permanently — blocking them stops the rotation.";
        }
    }

    if ($verdict === 'MODERATE') {
        if ($asn_count === 0) {
            return "This traffic is mixed — {$pct_str} is from known scanning or proxy infrastructure, with legitimate traffic in the remainder. Review the top sources below before blocking.";
        } elseif ($asn_count === 1) {
            return "This traffic is mixed — {$pct_str} originates from {$org0} ({$asn0}) scanning infrastructure. The remainder appears to be legitimate traffic. Use the CIDR ranges below selectively, or filter by country before downloading block scripts.";
        } else {
            return "This traffic is mixed — {$pct_str} is from scanning infrastructure across {$asn_count} ASNs including {$org0} and {$org1}. The remainder appears legitimate. Review the top sources before blocking broadly.";
        }
    }

    // LOW verdict
    if ($asn_count === 0) {
        return "No significant threat patterns detected. Most traffic appears to be from residential or commercial ISPs.";
    } elseif ($asn_count === 1) {
        return "No significant threat patterns detected. One scanning ASN ({$org0}) is present but at low volume. Most traffic appears to be from residential or commercial ISPs.";
    } else {
        return "No significant threat patterns detected. A small number of scanning ASNs are present but at low volume. Most traffic appears to be from residential or commercial ISPs.";
    }
}

/**
 * Compute data for the AbuseIPDB verification callout.
 *
 * Returns null if the callout should not be shown (all scores null, or none > 80).
 * Returns ['count' => N, 'total' => N, 'avg' => N] if the callout should be shown.
 *
 * @param array $top25  Ranked IP entries, each may have 'abuse_score' (int|null, 0-100).
 * @return array|null
 */
function compute_abuseipdb_callout(array $top25): ?array
{
    $total_shown = count($top25);
    if ($total_shown === 0) return null;

    // Only score entries above threshold
    $high_scores = array_filter(
        array_column($top25, 'abuse_score'),
        fn($s) => $s !== null && $s > 80
    );

    if (count($high_scores) === 0) return null;

    $avg = (int) round(array_sum($high_scores) / count($high_scores));

    return [
        'count' => count($high_scores),
        'total' => $total_shown,
        'avg'   => $avg,
    ];
}
