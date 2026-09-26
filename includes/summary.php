<?php
/**
 * build_summary(): the D4/D5 fixed summary line for the lookup results page.
 *
 * Rendered once per lookup, server-side, and NOT filter-driven — it always
 * describes every resolved IP in the lookup, regardless of which chips the
 * user later clicks (design doc, Pass 1, D4). index.php renders its output
 * in the slot the old Threat CTA box used to occupy.
 *
 * Deliberately a pure function of $rows (no DB, no globals besides what the
 * caller already resolved) so it's unit-testable without a page or a
 * GeoIP database — see tests/SummaryTest.php.
 */

declare(strict_types=1);

// Hover text for every DROP label (table tag + summary). assets/js/workbench.js
// carries the same string; tests/DropExplainerTest.php keeps the two identical.
const DROP_EXPLAINER = "Spamhaus DROP (Don't Route Or Peer): this IP is in a netblock Spamhaus lists as hijacked or run by spam or cybercrime operations. Legitimate traffic from these ranges is rare.";

const SUMMARY_CATEGORY_LABELS = [
    'scanning'    => 'Scanning',
    'cloud'       => 'Cloud exit',
    'vpn'         => 'VPN/Proxy',
    'residential' => 'Residential',
    'unknown'     => 'Unknown',
];

/**
 * @param array<int, array{category: string, asn: string, asn_org: string, drop: bool}> $rows
 *        One entry per resolved (looked up) IP. `asn` is the "AS12345" form
 *        (or '' when unknown); `drop` is whether the IP fell inside a
 *        Spamhaus DROP netblock (IPv4-only upstream — v6 rows always pass
 *        drop=false).
 *
 * @return array{
 *   total: int,
 *   categories: list<array{key: string, label: string, count: int, pct: int}>,
 *   top_asns: list<array{asn: string, org: string, count: int}>,
 *   drop_count: int,
 *   top_asn: ?array{asn: string, org: string, count: int},
 *   line: string,
 * }
 */
function build_summary(array $rows): array
{
    $total = count($rows);

    if ($total === 0) {
        return [
            'total' => 0,
            'categories' => [],
            'top_asns' => [],
            'drop_count' => 0,
            'top_asn' => null,
            'line' => '',
        ];
    }

    // ── Category breakdown: base = every resolved row (fixed, not filtered). ──
    $counts = array_fill_keys(array_keys(SUMMARY_CATEGORY_LABELS), 0);
    $drop_count = 0;
    $asn_counts = []; // 'AS14061' => ['org' => 'DigitalOcean', 'count' => n]

    foreach ($rows as $row) {
        $cat = $row['category'] ?? 'unknown';
        if (!isset($counts[$cat])) {
            $cat = 'unknown';
        }
        $counts[$cat]++;

        if (!empty($row['drop'])) {
            $drop_count++;
        }

        $asn = $row['asn'] ?? '';
        if ($asn !== '') {
            if (!isset($asn_counts[$asn])) {
                $asn_counts[$asn] = ['org' => $row['asn_org'] ?? '', 'count' => 0];
            }
            $asn_counts[$asn]['count']++;
        }
    }

    // Zero-count categories are omitted (D4). Non-zero ones are ordered by
    // count descending (ties broken by the fixed chip-vocabulary order) —
    // this matches the design doc's worked example, which lists Cloud exit
    // (61%) before Scanning (18%) before VPN/Proxy (6%).
    $vocab_order = array_flip(array_keys(SUMMARY_CATEGORY_LABELS));
    $categories = [];
    foreach ($counts as $key => $count) {
        if ($count === 0) {
            continue;
        }
        $categories[] = [
            'key'   => $key,
            'label' => SUMMARY_CATEGORY_LABELS[$key],
            'count' => $count,
            'pct'   => (int) round(($count / $total) * 100),
        ];
    }
    usort($categories, static function (array $a, array $b) use ($vocab_order): int {
        if ($a['count'] !== $b['count']) {
            return $b['count'] <=> $a['count'];
        }
        return $vocab_order[$a['key']] <=> $vocab_order[$b['key']];
    });

    // Top 3 ASNs by unique IPs (each row is already one unique IP, so a
    // straight count per ASN is a unique-IP count). Stable sort keeps
    // first-seen order among ties.
    $top_asns = [];
    foreach ($asn_counts as $asn => $info) {
        $top_asns[] = ['asn' => $asn, 'org' => $info['org'], 'count' => $info['count']];
    }
    usort($top_asns, static fn(array $a, array $b): int => $b['count'] <=> $a['count']);
    $top_asns = array_slice($top_asns, 0, 3);

    // Single leading ASN (IPG-33): only claim a "Top ASN" when the leader
    // actually leads — at least 2 IPs, and strictly more than the runner-up.
    // A 1-IP "top" or a tie between the top two is not a finding.
    $top_asn = null;
    if (!empty($top_asns) && $top_asns[0]['count'] >= 2
        && (count($top_asns) === 1 || $top_asns[0]['count'] > $top_asns[1]['count'])) {
        $top_asn = $top_asns[0];
    }

    // ── Render the line (IPG-33: DROP count + single top ASN only) ────────
    $parts = [];
    if ($drop_count === 1) {
        $parts[] = '1 IP in a Spamhaus DROP netblock';
    } elseif ($drop_count > 1) {
        $parts[] = number_format($drop_count) . ' IPs in Spamhaus DROP netblocks';
    }
    if ($top_asn !== null) {
        $asn_text = trim($top_asn['asn'] . ' ' . $top_asn['org']);
        $parts[] = 'Top ASN: ' . $asn_text . ' (' . number_format($top_asn['count']) . ' IPs)';
    }

    return [
        'total' => $total,
        'categories' => $categories,
        'top_asns' => $top_asns,
        'drop_count' => $drop_count,
        'top_asn' => $top_asn,
        'line' => implode(' · ', $parts),
    ];
}
