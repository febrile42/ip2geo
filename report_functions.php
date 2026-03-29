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
