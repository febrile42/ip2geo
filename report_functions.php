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
 * @param int $scanning_proxy  Number of IPs classified scanning or vpn
 * @param int $total           Total IP count (denominator)
 * @return string  'HIGH' | 'MODERATE' | 'LOW'
 */
function compute_verdict(int $scanning_proxy, int $total): string {
    if ($total === 0) return 'LOW';

    $pct = $scanning_proxy / $total;

    if ($pct >= 0.80 || ($pct >= 0.60 && $scanning_proxy >= 100)) {
        return 'HIGH';
    }

    if ($pct < 0.30 || $scanning_proxy < 10) {
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
