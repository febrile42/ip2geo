<?php
/**
 * Shared pure functions used by report.php and the test suite.
 *
 * Keeping these here (not embedded inline) makes them unit-testable
 * without booting the full page or a DB connection.
 */

// Kill switch for the Spamhaus DROP reputation axis (the residential-attacker CTA
// override on the lookup page, and the DROP surfaces in the threat reports). Flip
// to false to disable all of it instantly without a code change to the hot loop —
// handy if the override ever misfires in prod. Defined here (loaded by both
// index.php and report.php) so the gate is in scope on both entry points.
if (!defined('REPUTATION_AXIS_ENABLED')) {
    define('REPUTATION_AXIS_ENABLED', true);
}

// Spamhaus DROP reputation data. Two globals, both machine-generated weekly by
// .github/workflows/sync-spamhaus-drop.yml (that file is never hand-edited):
//   $spamhaus_drop_ranges — sorted, non-overlapping [start_int, end_int] pairs;
//                           the O(log n) membership hot path (ip_in_spamhaus_drop).
//   $spamhaus_drop_cidrs  — the un-merged originals [start_int, end_int, "cidr"],
//                           sorted by start; used by the report to name + block the
//                           specific netblock (spamhaus_drop_cidr_for_ip).
require_once __DIR__ . '/spamhaus_drop_data.php';

/**
 * Is an IPv4 address (as an unsigned 32-bit int) inside any Spamhaus DROP range?
 *
 * DROP lists netblocks controlled by criminals/hijackers, so a hit is a high-
 * confidence "this IP is bad" signal independent of ASN classification. Used by
 * the lookup hot loop to fire the threat CTA on residential attackers that the
 * ASN-based verdict would otherwise miss.
 *
 * Binary search over the sorted, disjoint $spamhaus_drop_ranges → O(log n).
 *
 * @param int $ip_int  Unsigned 32-bit IPv4 as int. Pass (int) ipToLong($ip);
 *                     ipToLong() returns sprintf('%u', ip2long($ip)) as a string,
 *                     and IPv6/invalid IPs collapse to 0 (never listed in DROP).
 * @return bool
 */
function ip_in_spamhaus_drop(int $ip_int): bool {
    global $spamhaus_drop_ranges;
    $lo = 0;
    $hi = count($spamhaus_drop_ranges) - 1;
    while ($lo <= $hi) {
        $mid = intdiv($lo + $hi, 2);
        if ($ip_int < $spamhaus_drop_ranges[$mid][0]) {
            $hi = $mid - 1;
        } elseif ($ip_int > $spamhaus_drop_ranges[$mid][1]) {
            $lo = $mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

/**
 * Name the specific Spamhaus DROP CIDR an IPv4 address sits in, or null.
 *
 * The merged $spamhaus_drop_ranges used by ip_in_spamhaus_drop() drops CIDR
 * boundaries, so it can't tell you *which* netblock to block. This searches the
 * un-merged $spamhaus_drop_cidrs (sorted ascending by start) for the covering
 * CIDR; on overlap it returns the most-specific (longest-prefix / smallest)
 * range, which is the one you actually want to name and block.
 *
 * Runs only on report IPs (≤25 per report), so correctness beats micro-perf:
 * a binary search lands near the candidate region, then a short linear scan
 * walks the few entries whose start is ≤ $ip_int and keeps the tightest cover.
 *
 * @param int $ip_int  Unsigned 32-bit IPv4 as int (same encoding as ip_in_spamhaus_drop()).
 * @return string|null The covering CIDR string, most-specific on overlap, or null if unlisted.
 */
function spamhaus_drop_cidr_for_ip(int $ip_int): ?string {
    global $spamhaus_drop_cidrs;
    $cidrs = $spamhaus_drop_cidrs ?? [];
    $n = count($cidrs);
    if ($n === 0) {
        return null;
    }

    // Binary search for the last entry whose start <= $ip_int. Everything that
    // can possibly cover $ip_int starts at or before it.
    $lo = 0;
    $hi = $n - 1;
    $idx = -1;
    while ($lo <= $hi) {
        $mid = intdiv($lo + $hi, 2);
        if ($cidrs[$mid][0] <= $ip_int) {
            $idx = $mid;
            $lo = $mid + 1;
        } else {
            $hi = $mid - 1;
        }
    }
    if ($idx < 0) {
        return null; // every CIDR starts after $ip_int
    }

    // Walk backwards over candidates (start <= $ip_int), keeping the tightest
    // cover. A containing block has a smaller start, so scanning back from $idx
    // reaches it; we stop early once no remaining entry can still cover $ip_int.
    $best        = null;
    $best_span   = PHP_INT_MAX;
    for ($i = $idx; $i >= 0; $i--) {
        [$start, $end, $cidr] = $cidrs[$i];
        if ($end >= $ip_int) {                 // covers the IP
            $span = $end - $start;
            if ($span < $best_span) {          // tighter (more-specific) cover
                $best      = $cidr;
                $best_span = $span;
                if ($span === 0) {
                    break;                     // /32 — can't get more specific
                }
            }
        }
    }

    return $best;
}

/**
 * Apply the Spamhaus DROP reputation override to a computed verdict + CTA state.
 *
 * A DROP hit is high-confidence criminal/hijacked space. Any hit (with the
 * existing >=5-IP floor) opens the CTA and floors the verdict at MODERATE, even
 * when the ASN-based verdict is LOW — this is what makes a residential fail2ban
 * paste fire. reputation_count == 0 returns the inputs unchanged (regression-safe).
 *
 * Pure: extracted from the index.php lookup path so it is unit-testable.
 * The REPUTATION_AXIS_ENABLED kill switch is checked by the caller.
 *
 * @param string $verdict_level   'HIGH' | 'MODERATE' | 'LOW'
 * @param bool   $show_cta        Whether the CTA would show pre-override
 * @param int    $matches_total   Non-good-country IP count (the >=5 floor)
 * @param int    $reputation_count Count of IPs on the Spamhaus DROP list
 * @param string $verdict_reason  Reason string computed pre-override ('' if none)
 * @return array{verdict_level:string, show_cta:bool, verdict_reason:string}
 */
function apply_reputation_override(
    string $verdict_level,
    bool $show_cta,
    int $matches_total,
    int $reputation_count,
    string $verdict_reason
): array {
    if ($matches_total >= 5 && $reputation_count >= 1) {
        $show_cta = true;
        if ($verdict_level === 'LOW') {
            $verdict_level = 'MODERATE';
        }
        if ($verdict_reason === '') {
            $verdict_reason = $reputation_count . ' IP' . ($reputation_count === 1 ? '' : 's')
                . ' on the Spamhaus DROP list (hijacked/criminal netblocks).';
        }
    }
    return [
        'verdict_level'  => $verdict_level,
        'show_cta'       => $show_cta,
        'verdict_reason' => $verdict_reason,
    ];
}

/**
 * Compute the Spamhaus DROP report data for one submission.
 *
 * Shared by the free and paid report generators (and unit-tested directly):
 *   - tags each $top25 entry with 'on_drop' (membership of its IP),
 *   - counts drop_count across ALL submitted IPs (not just the shown top 25),
 *   - (paid only) collects drop_ranges = the unique covering CIDRs, sorted.
 *
 * Empty/unlisted submissions yield drop_count = 0 and (when requested)
 * drop_ranges = [] — the caller stores those defaults so old cached reports,
 * which carry neither key, render unchanged.
 *
 * Pure: no DB, no network; backed by the in-memory Spamhaus DROP globals.
 *
 * @param array $all_ips       Every submitted IP entry (each has 'ip').
 * @param array $top25         The ranked top-25 entries to tag in place.
 * @param bool  $with_ranges   True on the paid tier to also build drop_ranges.
 * @return array{top25:array, drop_count:int, drop_ranges:array<int,string>}
 */
function compute_drop_report_data(array $all_ips, array $top25, bool $with_ranges): array
{
    // IPv4 string → unsigned 32-bit int; IPv6/invalid → 0 (never listed in DROP).
    // Mirrors ipToLong() in index.php; inlined so this stays DB- and page-free.
    $to_int = static function ($ip): int {
        $long = ip2long((string) $ip);
        return $long === false ? 0 : (int) sprintf('%u', $long);
    };

    $drop_count  = 0;
    $drop_ranges = [];

    foreach ($all_ips as $e) {
        $ip_int = $to_int($e['ip'] ?? '');
        if ($ip_int !== 0 && ip_in_spamhaus_drop($ip_int)) {
            $drop_count++;
            if ($with_ranges) {
                $cidr = spamhaus_drop_cidr_for_ip($ip_int);
                if ($cidr !== null) {
                    $drop_ranges[$cidr] = true;
                }
            }
        }
    }

    foreach ($top25 as &$entry) {
        $ip_int = $to_int($entry['ip'] ?? '');
        $entry['on_drop'] = ($ip_int !== 0 && ip_in_spamhaus_drop($ip_int));
    }
    unset($entry);

    if ($with_ranges) {
        $drop_ranges = array_keys($drop_ranges);
        sort($drop_ranges);
    }

    return [
        'top25'       => $top25,
        'drop_count'  => $drop_count,
        'drop_ranges' => $drop_ranges,
    ];
}

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
 * Build the inline threat-score teaser shown in the lookup CTA box.
 *
 * Pure: no DB, no network. Takes the already-enriched top entries plus the
 * flagged-IP count computed at verdict time.
 *
 * IMPORTANT: locked_count comes from $flagged_count (the scanning/proxy IP
 * count), NOT from the enriched scores. The inline path only enriches the top
 * 1-2 IPs live, so the rest carry abuse_score = null; counting scores above the
 * threshold across the (mostly-null) list would read ~0 on a cold cache — the
 * common first-investigation case. The honest number we already have is the
 * flagged count.
 *
 * @param array $enriched      Top entries; each may have 'ip' (string) and 'abuse_score' (int|null)
 * @param int   $flagged_count Count of flagged (scanning/proxy) IPs — the locked_count source
 * @param int   $threshold     Min confidence to reveal a sample score (default 80 = verified-attacker bar)
 * @param int   $drop_count    Count of IPs on the Spamhaus DROP list — free, zero-quota proof.
 *                             Primary proof for the residential-trigger case where flagged_count
 *                             (and thus live AbuseIPDB enrichment) is 0.
 * @return array{samples: array<int,array{ip:string,score:int}>, locked_count:int, drop_count:int}
 */
function build_teaser(array $enriched, int $flagged_count, int $threshold = 80, int $drop_count = 0): array {
    $samples = [];
    foreach ($enriched as $e) {
        $score = $e['abuse_score'] ?? null;
        if ($score !== null && (int)$score > $threshold) {
            $samples[] = ['ip' => (string)($e['ip'] ?? ''), 'score' => (int)$score];
            if (count($samples) >= 2) break; // at most 2 proof scores
        }
    }
    return [
        'samples'      => $samples,
        'locked_count' => max(0, $flagged_count),
        'drop_count'   => max(0, $drop_count),
    ];
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

    $https      = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on')
                  || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    $scheme     = $https ? 'https' : 'http';
    $host       = $_SERVER['HTTP_HOST'] ?? 'ip2geo.org';
    $report_url = $scheme . '://' . $host . '/report.php?token=' . urlencode($token);

    // Phase 3 — session_id for behavioral tracking (must be set before any output)
    $sid_cookie = 'report_sid_' . $token;
    if (!empty($_COOKIE[$sid_cookie]) && preg_match('/^[0-9a-f]{32}$/', $_COOKIE[$sid_cookie])) {
        $session_id = $_COOKIE[$sid_cookie];
    } else {
        $session_id = bin2hex(random_bytes(16)); // 32-char hex
        setcookie($sid_cookie, $session_id, [
            'expires'  => time() + 1800,
            'path'     => '/',
            'samesite' => 'Strict',
            'httponly' => false,
            'secure'   => $https,
        ]);
    }

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

    $free_nav = [
        ['label' => 'Summary',      'href' => '#report'],
        ['label' => 'Top Sources',  'href' => '#top-sources'],
        ['label' => '← New Lookup', 'href' => '/'],
    ];
    render_page_open('IP Threat Report — ip2geo.org', '', $og, $free_nav);
    ?>
    <section id="report" class="report-section">
        <div class="report-inner">

            <!-- 1. Verdict banner -->
            <div class="threat-cta-box threat-cta-box--<?php echo htmlspecialchars($verdict_lc, ENT_QUOTES, 'UTF-8'); ?>" role="region" aria-label="Threat Assessment">
                <div class="threat-cta-left">
                    <p class="asn-verdict asn-verdict--<?php echo htmlspecialchars($verdict_lc, ENT_QUOTES, 'UTF-8'); ?>">
                        <?php echo htmlspecialchars($verdict, ENT_QUOTES, 'UTF-8'); ?> THREAT
                    </p>
                    <p class="threat-cta-stats"><?php echo $scan_pct; ?>% of IPs from scanning or proxy infrastructure
                        (<?php echo $scan_count; ?> of <?php echo $total; ?> IPs)</p>
                </div>
            </div>

            <!-- Spamhaus DROP count line (only when listed IPs are present) -->
            <?php $drop_count = (int)($report['drop_count'] ?? 0); if ($drop_count > 0): ?>
            <p class="report-drop-count">
                <strong><?php echo number_format($drop_count); ?></strong> of these IPs sit in Spamhaus DROP netblocks &mdash; ranges confirmed under criminal control.
            </p>
            <?php endif; ?>

            <!-- 2. Upgrade CTA -->
            <div class="free-report-upgrade">
                <p class="free-report-upgrade__headline">Confirm which of these IPs are active attackers &mdash; $9</p>
                <ul class="free-report-upgrade__features">
                    <li><strong>Threat confidence scores</strong> for all <?php echo count($top25); ?> IPs &mdash; verified against recent attack reports</li>
                    <li><strong>ASN CIDR ranges</strong> &mdash; block entire scanning networks, not just individual IPs that rotate</li>
                    <li><strong>Firewall scripts</strong> &mdash; ready-to-run rules for iptables, ufw, and nginx</li>
                    <li><strong>Permanent link</strong> &mdash; save this report before it expires</li>
                </ul>
                <form method="POST" action="/get-report.php">
                    <input type="hidden" name="action" value="upgrade">
                    <input type="hidden" name="upgrade_token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="button" onclick="window.umami && umami.track('upgrade_cta_click')">Unlock Threat Scores &mdash; $9</button>
                </form>
                <p class="free-report-upgrade__fine">One-time payment. No re-upload needed.</p>
            </div>

            <!-- 3. Top-25 table with locked Threat Score column -->
            <h2 id="top-sources">Top Threat Sources</h2>
            <p class="report-table-note">Ranked by threat weight (scanning/VPN IPs weighted 2&times;).</p>
            <div class="report-table-wrap">
            <table class="report-free-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP</th>
                        <th>Country</th>
                        <th>ASN</th>
                        <th>Category</th>
                        <th class="col-right">Hits</th>
                        <th class="col-locked" title="Upgrade to unlock">Threat Score &#128274;</th>
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
                        <td class="col-num"><?php echo $i + 1; ?></td>
                        <td class="col-mono"><?php echo $ip_safe; ?></td>
                        <td><?php echo $cc_safe ?: '—'; ?></td>
                        <td class="col-asn">
                            <?php if ($asn_safe !== ''): ?>
                            <span><?php echo $asn_safe; ?></span>
                            <?php if ($org_safe !== ''): ?><span class="asn-org"><?php echo $org_safe; ?></span><?php endif; ?>
                            <?php else: ?>&mdash;<?php endif; ?>
                        </td>
                        <td class="cell-asn-category"><span class="asn-category asn-category--<?php echo $cat_safe; ?>"><?php echo $cat_safe; ?></span><?php if (!empty($entry['on_drop'])): ?> <span class="drop-flag" title="On the Spamhaus DROP list (criminal/hijacked netblock)">DROP</span><?php endif; ?></td>
                        <td class="col-right"><?php echo number_format($freq); ?></td>
                        <td class="col-locked">&mdash;</td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>

            <!-- 4. Expiry banner -->
            <?php if ($expiry_text !== null): ?>
            <div class="free-report-expiry">
                <?php echo $expiry_text; ?> <a href="/">Analyze new logs &rarr;</a>
            </div>
            <?php endif; ?>

            <!-- 5. Sharing links -->
            <div class="free-report-share">
                <p class="free-report-share-label">Share this report</p>
                <div class="free-report-share-row">
                    <button class="button small alt" id="free-copy-btn"
                        onclick="(function(btn){navigator.clipboard?navigator.clipboard.writeText(<?php echo json_encode($report_url); ?>).then(function(){btn.textContent='Copied!';setTimeout(function(){btn.textContent='Copy link'},2000)}):btn.textContent='Copy link';})(this)">Copy link</button>
                    <input type="text" class="free-report-share-input" readonly
                        value="<?php echo htmlspecialchars($report_url, ENT_QUOTES, 'UTF-8'); ?>"
                        onclick="this.select()">
                </div>
            </div>

            <!-- 6. Footer attribution -->
            <p class="report-footer-note">
                Generated with <a href="/">ip2geo.org</a> &mdash; paste your logs, get instant threat intel.
            </p>

        </div>
    </section>
    <script>
    (function() {
        var REPORT_SID = <?php echo json_encode($session_id); ?>;
        var VERDICT    = <?php echo json_encode($verdict_lc); ?>;
        var TOKEN      = <?php echo json_encode($token); ?>;
        var TOTAL      = <?php echo (int)$total; ?>;
        var BUCKET     = TOTAL <= 10 ? '1-10' : TOTAL <= 50 ? '11-50' : TOTAL <= 200 ? '51-200'
                       : TOTAL <= 1000 ? '201-1000' : TOTAL <= 5000 ? '1001-5000' : '5000+';
        var startTime  = Math.floor(Date.now() / 1000);
        var exitFired  = false;

        function sendEvent(type) {
            if (!navigator.sendBeacon) return;
            navigator.sendBeacon('/api/report-event.php', JSON.stringify(
                {token: TOKEN, event_type: type, session_id: REPORT_SID}
            ));
        }

        // Phase 1 (existing Umami event, kept on load for deferred script compat)
        window.addEventListener('load', function() {
            window.umami && umami.track('free_report_view', {verdict: VERDICT});
        });

        // Phase 3: page_viewed on entry
        sendEvent('page_viewed');

        // Phase 1a + Phase 3: exit handlers share exitFired flag
        function onExit() {
            if (exitFired) return;
            exitFired = true;
            var secs = Math.min(600, Math.floor(Date.now() / 1000) - startTime);
            window.umami && umami.track('report_dwell', {
                seconds_on_page: secs, verdict: VERDICT, ip_count_bucket: BUCKET
            });
            sendEvent('page_viewed'); // marks session end for MAX(event_at) dwell calc
        }

        document.addEventListener('visibilitychange', function() {
            if (document.visibilityState === 'hidden') {
                onExit();
            } else {
                exitFired = false; // reset for next exit cycle
                startTime = Math.floor(Date.now() / 1000);
                sendEvent('page_viewed'); // return-to-tab
            }
        });
        window.addEventListener('pagehide', onExit);     // iOS Safari fallback
        window.addEventListener('beforeunload', onExit); // desktop last-resort

        // Phase 1b + Phase 3: cta_visible — single shared observer
        var ctaEl = document.querySelector('.free-report-upgrade');
        if (ctaEl && 'IntersectionObserver' in window) {
            var ctaTimer = null;
            var obs = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        ctaTimer = ctaTimer || setTimeout(function() {
                            window.umami && umami.track('cta_visible', {verdict: VERDICT});
                            sendEvent('cta_visible');
                            obs.disconnect();
                        }, 500);
                    } else {
                        clearTimeout(ctaTimer);
                        ctaTimer = null;
                    }
                });
            }, {threshold: 0.5});
            obs.observe(ctaEl);
        }

        // Phase 3: cta_clicked beacon (upgrade_cta_click Umami event is on the button already)
        var upgradeBtn = document.querySelector('.free-report-upgrade button[type="submit"]');
        if (upgradeBtn) {
            upgradeBtn.addEventListener('click', function() { sendEvent('cta_clicked'); });
        }
    })();
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

/**
 * Build script content lines for a given block-rule format.
 *
 * Returns one string per line, no trailing newlines. Used for both
 * the inline preview (<pre> blocks) and the file download path.
 *
 * @param string $format  One of: sh-iptables, sh-ufw, sh-iptables-ranges,
 *                        sh-ufw-ranges, nginx-ips, nginx-ranges, txt-ranges
 * @param array  $report  Report data array (block_ips, top25, asn_ranges)
 * @param string $token   Report token (included in script preamble comment)
 * @return string[]  Lines of the script, or [] for an unknown format
 */
function get_script_lines(string $format, array $report, string $token): array
{
    $valid = ['sh-iptables', 'sh-ufw', 'sh-iptables-ranges', 'sh-ufw-ranges', 'nginx-ips', 'nginx-ranges', 'txt-ranges'];
    if (!in_array($format, $valid, true)) return [];

    $ips   = !empty($report['block_ips']) ? $report['block_ips'] : array_column($report['top25'] ?? [], 'ip');
    // Spamhaus DROP netblocks lead the range scripts: they are confirmed
    // criminal-controlled space, the highest-confidence block we can offer.
    // (IP-only formats below never touch $cidrs, so they are unaffected.)
    $cidrs = $report['drop_ranges'] ?? [];
    foreach ($report['asn_ranges'] ?? [] as $group) {
        foreach ($group['cidrs'] as $cidr) {
            $cidrs[] = $cidr;
        }
    }

    if ($format === 'sh-iptables') {
        $preamble = '#!/bin/bash
# ip2geo threat report — iptables block rules
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($ips) . ' IPs flagged as scanning / proxy infrastructure

set -euo pipefail
';
        $body = $preamble . implode("\n", array_map(fn($ip) => 'iptables -A INPUT -s ' . $ip . ' -j DROP', $ips)) . "\n";
    } elseif ($format === 'sh-ufw') {
        $preamble = '#!/bin/bash
# ip2geo threat report — ufw block rules
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($ips) . ' IPs flagged as scanning / proxy infrastructure

set -euo pipefail
';
        $body = $preamble . implode("\n", array_map(fn($ip) => 'ufw deny from ' . $ip . ' to any', $ips)) . "\n";
    } elseif ($format === 'sh-iptables-ranges') {
        $preamble = '#!/bin/bash
# ip2geo threat report — iptables block rules (ASN ranges)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes

set -euo pipefail
';
        $body = $preamble . implode("\n", array_map(fn($cidr) => 'iptables -A INPUT -s ' . $cidr . ' -j DROP', $cidrs)) . "\n";
    } elseif ($format === 'sh-ufw-ranges') {
        $preamble = '#!/bin/bash
# ip2geo threat report — ufw block rules (ASN ranges)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes

set -euo pipefail
';
        $body = $preamble . implode("\n", array_map(fn($cidr) => 'ufw deny from ' . $cidr . ' to any', $cidrs)) . "\n";
    } elseif ($format === 'nginx-ips') {
        $preamble = '# ip2geo threat report — nginx geo block (individual IPs)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($ips) . ' IPs flagged as scanning / proxy infrastructure
# Usage: include this file inside a geo $blocked_ip { } block in nginx.conf

default 0;
';
        $body = $preamble . implode("\n", array_map(fn($ip) => $ip . ' 1;', $ips)) . "\n";
    } elseif ($format === 'nginx-ranges') {
        $preamble = '# ip2geo threat report — nginx geo block (ASN ranges)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# Block ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes
# Usage: include this file inside a geo $blocked_ip { } block in nginx.conf

default 0;
';
        $body = $preamble . implode("\n", array_map(fn($cidr) => $cidr . ' 1;', $cidrs)) . "\n";
    } else { // txt-ranges
        $preamble = '# ip2geo threat report — CIDR ranges (plain list)
# Generated: ' . date('Y-m-d') . '
# Token: ' . $token . '
# ' . count($cidrs) . ' CIDR ranges covering scanning/VPN ASN prefixes
# One range per line — paste into ipset, web firewall, or any blocklist tool
';
        $body = $preamble . implode("\n", $cidrs) . "\n";
    }

    return explode("\n", rtrim($body));
}

// ── AbuseIPDB enrichment ──────────────────────────────────────────────────────
// Moved here from report.php so non-report callers (the index.php inline
// threat-score teaser) can reuse it without including a whole page file.
// $timeout is the per-IP curl timeout: 10s on the report path, ~2s on the
// lookup hot path so a slow AbuseIPDB never stalls the results render.
//
// $live=false makes this CACHE-ONLY (no API calls, no quota): used by the inline
// teaser on large submissions, whose base geo lookup is already slow enough that
// adding a live call would blow the post-deploy perf budget. Recurring mass
// scanners still surface from cache at zero latency.
//
// Quota: a hard 1000/day cap (abuseipdb_daily_usage) with graceful degrade —
// over budget returns cached scores where available, null otherwise.

function enrich_abuseipdb(array $ips, $con, string $api_key, int $timeout = 10, bool $live = true): array {
    if ($api_key === '') {
        foreach ($ips as &$entry) $entry['abuse_score'] = null;
        return $ips;
    }

    $today = date('Y-m-d');

    // Separate cached vs uncached IPs. Cache hits (queried within 7 days) cost
    // no quota; only uncached IPs need a live call.
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

    $batch_size  = count($need_api);
    $api_results = [];

    if ($live && $batch_size > 0) {
        // Reserve the batch atomically BEFORE any network I/O. A single
        // conditional UPDATE both enforces the 1000/day cap and reserves the
        // slots, so two concurrent lookups can never both pass the cap (closes
        // the prior TOCTOU) and no row lock is held across the curl calls.
        $con->query(
            'INSERT INTO abuseipdb_daily_usage (usage_date, calls_made) VALUES ("' . $today . '", 0)
             ON DUPLICATE KEY UPDATE calls_made = calls_made'
        );
        $reserve = $con->prepare(
            'UPDATE abuseipdb_daily_usage
                SET calls_made = calls_made + ?
              WHERE usage_date = ? AND calls_made + ? <= 1000'
        );
        $reserve->bind_param('isi', $batch_size, $today, $batch_size);
        $reserve->execute();
        $reserved = ($reserve->affected_rows === 1);
        $reserve->close();

        if (!$reserved) {
            // Over the daily cap — degrade gracefully (cached where available).
            foreach ($ips as &$entry) {
                $entry['abuse_score'] = $cached_rows[$entry['ip']] ?? null;
            }
            unset($entry);
            return $ips;
        }

        // We reserved $batch_size slots. Reconcile unused reservations no matter
        // how we leave the curl block (exception included) so the counter
        // reflects calls actually made. A hard fatal would leak the small
        // reservation, which self-heals when usage_date rolls over at UTC midnight.
        $actual_calls = 0;
        try {
            $multi   = curl_multi_init();
            $handles = [];
            foreach ($need_api as $ip) {
                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL            => 'https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode($ip) . '&maxAgeInDays=90',
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT        => $timeout,
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

            // Cache successful results.
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
        } finally {
            // Return unused reservations (failed/timed-out calls) to the budget.
            $unused = $batch_size - $actual_calls;
            if ($unused > 0) {
                $con->query(
                    'UPDATE abuseipdb_daily_usage
                        SET calls_made = calls_made - ' . (int)$unused . '
                      WHERE usage_date = "' . $today . '"'
                );
            }
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
