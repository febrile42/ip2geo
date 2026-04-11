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
 * Render a free (7-day) threat report page.
 *
 * Layout (in order — hierarchy matters):
 *   1. Verdict banner + stats
 *   2. Top-25 table with locked AbuseIPDB column
 *   3. Upgrade CTA
 *   4. Expiry banner
 *   5. Sharing links
 *   6. Footer attribution
 *
 * No block scripts, no community consent banner.
 *
 * @param array       $report      Generated report data (verdict, top25, etc.)
 * @param string      $token       Free report token (UUID4)
 * @param string|null $expires_at  DATETIME string from DB, or null
 * @param array       $all_ips     Full ip_list_json for country/cat chips (unused in free render but kept for parity)
 */
function render_free_report(array $report, string $token, ?string $expires_at, array $all_ips): void
{
    $verdict    = $report['verdict'];
    $verdict_lc = strtolower($verdict);
    $total      = $report['total_ips'];
    $scan_pct   = $report['scanning_pct'];
    $scan_count = $report['scanning_count'];
    $top25      = $report['top25'];

    $report_url = 'https://ip2geo.org/report.php?token=' . urlencode($token);

    // Expiry countdown
    $expires_ts      = $expires_at ? strtotime($expires_at) : null;
    $seconds_left    = $expires_ts ? ($expires_ts - time()) : null;
    $days_left       = $seconds_left !== null ? (int)ceil($seconds_left / 86400) : null;
    $expiry_text     = null;
    if ($days_left !== null) {
        if ($days_left <= 0) {
            $expiry_text = 'This report has expired.';
        } elseif ($days_left === 1 || $seconds_left < 86400) {
            $expiry_text = 'This free report expires today.';
        } else {
            $expiry_text = 'This free report expires in <strong>' . $days_left . ' day' . ($days_left === 1 ? '' : 's') . '</strong>.';
        }
    }

    $og = [
        'title'       => 'IP Threat Report — ip2geo.org',
        'description' => $total . ' IPs analyzed · ' . $verdict . ' · ' . $scan_pct . '% scanning infrastructure',
        'url'         => $report_url,
    ];

    render_page_open('IP Threat Report — ip2geo.org', '', $og);
    ?>
    <section id="report" class="wrapper style4 fade-up">
        <div class="inner">

            <!-- 1. Verdict banner -->
            <div class="threat-cta-box threat-cta-box--<?php echo htmlspecialchars($verdict_lc, ENT_QUOTES, 'UTF-8'); ?>" style="margin-bottom:1.5em" role="region" aria-label="Threat Assessment">
                <div class="threat-cta-left">
                    <p class="asn-verdict asn-verdict--<?php echo htmlspecialchars($verdict_lc, ENT_QUOTES, 'UTF-8'); ?>">
                        <?php echo htmlspecialchars($verdict, ENT_QUOTES, 'UTF-8'); ?> THREAT
                    </p>
                    <p class="threat-cta-stats"><?php echo $scan_pct; ?>% of IPs from scanning or proxy infrastructure
                        (<?php echo $scan_count; ?> of <?php echo $total; ?> IPs)</p>
                </div>
            </div>

            <!-- 2. Top-25 table with locked AbuseIPDB column -->
            <h3 id="top-sources">Top Threat Sources</h3>
            <p style="font-size:0.85em;opacity:0.65">Ranked by threat weight (scanning/VPN IPs weighted 2×).</p>
            <div class="report-table-wrap" style="overflow-x:auto">
            <table class="report-table" style="width:100%;border-collapse:collapse;font-size:0.9em">
                <thead>
                    <tr>
                        <th style="text-align:left;padding:0.4em 0.6em">#</th>
                        <th style="text-align:left;padding:0.4em 0.6em">IP</th>
                        <th style="text-align:left;padding:0.4em 0.6em">Country</th>
                        <th style="text-align:left;padding:0.4em 0.6em">ASN</th>
                        <th style="text-align:left;padding:0.4em 0.6em">Category</th>
                        <th style="text-align:right;padding:0.4em 0.6em">Hits</th>
                        <th style="text-align:right;padding:0.4em 0.6em" title="Upgrade to unlock">Threat Score &#128274;</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($top25 as $i => $entry):
                        $ip_safe    = htmlspecialchars($entry['ip'] ?? '', ENT_QUOTES, 'UTF-8');
                        $cc_safe    = htmlspecialchars($entry['country'] ?? '', ENT_QUOTES, 'UTF-8');
                        $asn_safe   = htmlspecialchars($entry['asn'] ?? '', ENT_QUOTES, 'UTF-8');
                        $org_safe   = htmlspecialchars($entry['asn_org'] ?? '', ENT_QUOTES, 'UTF-8');
                        $cat_safe   = htmlspecialchars($entry['classification'] ?? 'unknown', ENT_QUOTES, 'UTF-8');
                        $freq       = (int)($entry['freq'] ?? 1);
                    ?>
                    <tr>
                        <td style="padding:0.3em 0.6em;opacity:0.5"><?php echo $i + 1; ?></td>
                        <td style="padding:0.3em 0.6em;font-family:monospace"><?php echo $ip_safe; ?></td>
                        <td style="padding:0.3em 0.6em"><?php echo $cc_safe ?: '—'; ?></td>
                        <td style="padding:0.3em 0.6em;font-size:0.85em">
                            <?php if ($asn_safe !== ''): ?>
                            <span><?php echo $asn_safe; ?></span>
                            <?php if ($org_safe !== ''): ?><span style="opacity:0.6"> <?php echo $org_safe; ?></span><?php endif; ?>
                            <?php else: ?>—<?php endif; ?>
                        </td>
                        <td style="padding:0.3em 0.6em"><span class="cat-chip cat-<?php echo $cat_safe; ?>"><?php echo ucfirst($cat_safe); ?></span></td>
                        <td style="padding:0.3em 0.6em;text-align:right"><?php echo number_format($freq); ?></td>
                        <td style="padding:0.3em 0.6em;text-align:right;opacity:0.35">—</td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
                <tfoot>
                    <tr>
                        <td colspan="7" style="padding:0.4em 0.6em;font-size:0.82em;opacity:0.55">Threat scores require upgrade</td>
                    </tr>
                </tfoot>
            </table>
            </div>

            <!-- 3. Upgrade CTA -->
            <div class="free-report-upgrade" style="margin:2em 0;padding:1.2em 1.4em;border-left:3px solid #e0a85a;background:rgba(224,168,90,0.08)">
                <p style="margin:0 0 0.8em;font-weight:bold">Unlock AbuseIPDB threat scores for all <?php echo count($top25); ?> IPs + permanent link &mdash; $9</p>
                <form method="POST" action="/get-report.php">
                    <input type="hidden" name="action" value="upgrade">
                    <input type="hidden" name="upgrade_token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="button" onclick="window.umami && umami.track('upgrade_cta_click')">Get Full Threat Report &mdash; $9</button>
                </form>
                <p style="margin:0.6em 0 0;font-size:0.82em;opacity:0.65">One-time payment. This report's IPs are saved &mdash; no re-upload needed.</p>
            </div>

            <!-- 4. Expiry banner -->
            <?php if ($expiry_text !== null): ?>
            <div class="free-report-expiry" style="margin:1.5em 0;padding:0.7em 1em;background:rgba(100,100,100,0.08);border-radius:4px;font-size:0.9em">
                <?php echo $expiry_text; ?> <a href="/" style="margin-left:0.4em;opacity:0.75">Analyze new logs →</a>
            </div>
            <?php endif; ?>

            <!-- 5. Sharing links -->
            <div class="free-report-share" style="margin:1.5em 0">
                <p style="margin:0 0 0.5em;font-size:0.9em;opacity:0.75">Share this report</p>
                <div style="display:flex;gap:0.5em;align-items:center;flex-wrap:wrap">
                    <button class="button small alt" id="free-copy-btn"
                        onclick="(function(btn){navigator.clipboard?navigator.clipboard.writeText('<?php echo htmlspecialchars($report_url, ENT_QUOTES, 'UTF-8'); ?>').then(function(){btn.textContent='Copied!';setTimeout(function(){btn.textContent='Copy link'},2000)}):btn.textContent='Copy link';})(this)">Copy link</button>
                    <input type="text" readonly
                        value="<?php echo htmlspecialchars($report_url, ENT_QUOTES, 'UTF-8'); ?>"
                        onclick="this.select()"
                        style="font-family:monospace;font-size:0.85em;padding:0.3em 0.6em;flex:1;min-width:0;max-width:36em">
                </div>
            </div>

            <!-- 6. Footer attribution -->
            <p style="margin-top:2em;font-size:0.82em;opacity:0.5;border-top:1px solid rgba(255,255,255,0.08);padding-top:1em">
                Generated with <a href="/" style="opacity:0.75">ip2geo.org</a> &mdash; paste your logs, get instant threat intel.
            </p>

        </div>
    </section>
    <script>
    window.umami && umami.track('free_report_view', {verdict: <?php echo json_encode(strtolower($verdict)); ?>});
    </script>
    <?php render_page_close();
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
