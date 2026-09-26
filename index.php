<?php

declare(strict_types=1);

require_once __DIR__ . '/asn_classification.php';
require_once __DIR__ . '/report_functions.php'; // ip_in_spamhaus_drop(), REPUTATION_AXIS_ENABLED
require_once __DIR__ . '/includes/extract.php';  // extract_ips(), EXTRACT_IPS_CAP
require_once __DIR__ . '/includes/lookup.php';   // lookup_ips(), GeoDbUnavailableException
require_once __DIR__ . '/includes/summary.php';  // build_summary(), SUMMARY_CATEGORY_LABELS
require_once __DIR__ . '/includes/version.php';  // APP_VERSION for ?v= asset URLs
require_once __DIR__ . '/includes/client-ip.php';  // lookup_endpoint_client_ip()
require_once __DIR__ . '/includes/rate-limit.php'; // default_lookup_rate_limiter(), 60/min/IP
@include_once __DIR__ . '/db_version.php'; // gitignored; written by the monthly DB update script
if (is_file(__DIR__ . '/config.php')) {
    // Optional in v5: index.php no longer talks to MySQL or Stripe (R17), so
    // the only thing it might still read from here is a GEOIP_MMDB_DIR
    // override.
    require_once __DIR__ . '/config.php';
}

function ipToLong(string $ip): string {
    return sprintf('%u', ip2long($ip)); // Handles unsigned 32-bit int
}

/**
 * The visitor's own IP (R16's "(you)" sample line). Prefers Cloudflare's
 * header — lime sits behind Cloudflare — then falls back to the historical
 * header order. No anti-spoofing check: R16's accepted scope is "we don't
 * care if someone is intentionally spoofing, it's a demo" (a spoofed value
 * only ever mislabels the spoofer's own sample-log row).
 */
function getRealIPAddr(): string
{
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
}

/**
 * index.php must never be served from a shared cache (R16): the "(you)"
 * sample line puts the visitor's own IP in the markup. A single helper so
 * the value is asserted the same way in tests as it's sent on the wire.
 */
function ip2geo_index_cache_control(): string
{
    return 'private, no-store';
}

/**
 * Middle-truncated display form for a canonical IPv6 address, per D15:
 * "2001:db8::7334" -> "2001:db8…:7334". Mobile-only in CSS (.ip-truncated);
 * the full address always stays in the DOM (.ip-full, and the cell's title
 * attribute) for the title tooltip and for CSV/copy.
 */
function ipv6_middle_truncate(string $ip): string
{
    if (strlen($ip) <= 15) {
        return $ip;
    }
    return substr($ip, 0, 8) . "\u{2026}:" . substr($ip, -4);
}

/**
 * All raw IP-shaped candidates in $text, public AND private — used only to
 * tell the EMPTY state apart from the PRIVATE-ONLY state (D6). This reuses
 * includes/extract.php's private-range predicates and IPv6 validator rather
 * than reimplementing them; unlike extract_ips() it keeps private hits
 * instead of dropping them, which is the one piece of information
 * extract_ips()'s return value doesn't carry.
 *
 * @return string[] unique, normalized IP strings (v4 as-is, v6 canonical)
 */
function extract_raw_ip_candidates(string $text): array
{
    preg_match_all(
        "/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/",
        $text,
        $v4
    );
    preg_match_all('/[0-9A-Fa-f:.]+/', $text, $v6c);

    $seen = [];
    foreach ($v4[0] as $ip) {
        $seen[$ip] = true;
    }
    foreach ($v6c[0] as $token) {
        if (strpos($token, ':') === false) {
            continue;
        }
        $normalized = extract_ips_validate_v6_candidate($token);
        if ($normalized !== null) {
            $seen[$normalized] = true;
        }
    }
    return array_keys($seen);
}

/**
 * Renders the #results section for one submitted lookup: the D6/D7 state
 * table (empty, private-only, over-10k notice, 503), the D4/D5 fixed
 * summary line, DROP tags, the "(you)" row (R16), and the results table.
 *
 * Pulled out of the page flow so it's callable — and unit-testable — without
 * booting the full HTML page or a real GeoIP database; see
 * tests/IndexResultsTest.php. Define IP2GEO_SKIP_PAGE_RENDER before
 * requiring this file to get this function (and the others above) without
 * executing the page body below.
 *
 * @param array{ip_list?: string, countries_filter?: string} $post   like $_POST
 * @param string      $visitor_ip  the requester's own IP (R16); '' if unknown/invalid
 * @param string|null $city_db     optional GeoLite2-City.mmdb path override (tests)
 * @param string|null $asn_db      optional GeoLite2-ASN.mmdb path override (tests)
 */
function render_lookup_results(array $post, string $visitor_ip = '', ?string $city_db = null, ?string $asn_db = null): string
{
    $section_open  = '<section id="results" class="block"><div class="section-head"><h2 id="result">Lookup Results</h2><span class="section-tag">01 / Results</span></div>';
    $section_close = '</section>';

    $raw_ip_list = (string) ($post['ip_list'] ?? '');

    // OVER 2 MB (D6)
    if (strlen($raw_ip_list) > 2097152) {
        return $section_open
            . '<p class="notice" role="alert">Paste is over 2 MB. Trim it or paste the busiest part of the log.</p>'
            . $section_close;
    }

    $extracted    = extract_ips($raw_ip_list);
    $ip_freq      = $extracted['ips']; // [ip => count], v4+v6, capped, private-filtered
    $total_unique = $extracted['total_unique'];

    // EMPTY / PRIVATE-ONLY (D6)
    if (empty($ip_freq)) {
        $raw_candidates = extract_raw_ip_candidates($raw_ip_list);
        if (empty($raw_candidates)) {
            return $section_open
                . '<p class="notice" role="status">No IP addresses found in the pasted text.</p>'
                . $section_close;
        }
        $n = count($raw_candidates);
        return $section_open
            . '<p class="notice" role="status">Found ' . number_format($n) . ' address' . ($n === 1 ? '' : 'es')
            . ', all private or internal (10/8, 172.16/12, 192.168/16, ::1, fc00::/7). Nothing to look up.</p>'
            . $section_close;
    }

    // OVER 10k UNIQUE notice (D7) — extract_ips() already capped $ip_freq;
    // total_unique is the pre-cap count, so the gap between them is what got skipped.
    $notice_html = '';
    if ($total_unique > EXTRACT_IPS_CAP) {
        $looked_up = count($ip_freq);
        $skipped   = $total_unique - $looked_up;
        $notice_html = '<p class="notice" role="status">Looked up the first ' . number_format($looked_up)
            . ' of ' . number_format($total_unique) . ' unique IPs. ' . number_format($skipped)
            . ' skipped. Paste the rest separately to check them.</p>';
    }

    // Country exclude filter — sanitized 2-letter codes. The DB whitelist
    // query this used to validate against is gone with MySQL; an unknown
    // code simply never matches any row, same net effect.
    $good_countries = array_values(array_filter(
        array_map(
            static fn(string $c): string => strtoupper(trim($c)),
            preg_split('/\s+/', (string) ($post['countries_filter'] ?? ''), -1, PREG_SPLIT_NO_EMPTY) ?: []
        ),
        static fn(string $c): bool => (bool) preg_match('/^[A-Z]{2}$/', $c)
    ));

    // ── GeoIP + ASN lookup, IPv4 AND IPv6 in one pass (R4) ──
    try {
        $lookup = lookup_ips(array_keys($ip_freq), $city_db, $asn_db);
    } catch (GeoDbUnavailableException $e) {
        // 503 state (D6) — a missing or mid-swap .mmdb file, not a bug in the paste.
        return $section_open
            . '<p class="notice" role="alert">Lookup data is updating. Try again in a minute.</p>'
            . $section_close;
    }

    $rows_for_summary = [];
    $rows_html         = '';
    $no_result_ips      = [];
    $country_counts      = [];
    $filtered_total       = 0;

    foreach ($ip_freq as $ip => $freq) {
        $geo   = $lookup[$ip] ?? null;
        $is_v6 = strpos($ip, ':') !== false;

        $asn_num      = $geo['autonomous_system_number'] ?? null;
        $asn_org      = $geo['autonomous_system_org'] ?? '';
        $country_code = $geo['country_iso_code'] ?? '';
        $country_name = $geo['country_name'] ?? '';
        $region       = $geo['subdivision_1_name'] ?? '';
        $city         = $geo['city_name'] ?? '';

        $has_geo = $geo !== null && ($country_code !== '' || $asn_num !== null);
        if (!$has_geo) {
            $no_result_ips[] = $ip;
            continue;
        }

        if (in_array($country_code, $good_countries, true)) {
            $filtered_total++;
            continue;
        }

        $category = classify_asn((string) ($asn_num ?? ''), (string) $asn_org);
        // Spamhaus DROP is an IPv4-only netblock list; v6 rows never match.
        $drop = (!$is_v6 && REPUTATION_AXIS_ENABLED)
            ? ip_in_spamhaus_drop((int) ipToLong($ip))
            : false;

        $rows_for_summary[] = [
            'category' => $category,
            'asn'      => $asn_num !== null ? 'AS' . $asn_num : '',
            'asn_org'  => $asn_org,
            'drop'     => $drop,
        ];

        if ($country_code !== '') {
            $country_counts[$country_code] = ($country_counts[$country_code] ?? 0) + 1;
        }

        $is_you = $visitor_ip !== '' && $ip === $visitor_ip;

        if ($is_v6) {
            $ip_safe = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
            $ip_cell = '<span class="ip-full">' . $ip_safe . '</span><span class="ip-truncated">' . htmlspecialchars(ipv6_middle_truncate($ip), ENT_QUOTES, 'UTF-8') . '</span>';
            $ip_title = ' title="' . $ip_safe . '"';
        } else {
            $ip_cell = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
            $ip_title = '';
        }

        $rows_html .= '<tr data-category="' . htmlspecialchars($category, ENT_QUOTES, 'UTF-8') . '" data-country="' . htmlspecialchars($country_code, ENT_QUOTES, 'UTF-8') . '">';
        $rows_html .= '<td class="cell-ip"' . $ip_title . '>' . $ip_cell . ($is_you ? ' <span class="you-tag">(you)</span>' : '') . '</td>';
        $rows_html .= '<td><abbr title="' . htmlspecialchars($country_name, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($country_code, ENT_QUOTES, 'UTF-8') . '</abbr></td>';
        $rows_html .= '<td class="cell-region">' . htmlspecialchars($region, ENT_QUOTES, 'UTF-8') . '</td>';
        $rows_html .= '<td class="cell-city">' . htmlspecialchars($city, ENT_QUOTES, 'UTF-8') . '</td>';
        $rows_html .= '<td>' . htmlspecialchars($asn_num !== null ? 'AS' . $asn_num : '', ENT_QUOTES, 'UTF-8') . '</td>';
        $rows_html .= '<td class="cell-asn-org" title="' . htmlspecialchars($asn_org, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($asn_org, ENT_QUOTES, 'UTF-8') . '</td>';
        $rows_html .= '<td class="asn-category asn-category--' . htmlspecialchars($category, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($category, ENT_QUOTES, 'UTF-8')
            . ($drop ? ' <abbr class="drop-tag" title="' . htmlspecialchars(DROP_EXPLAINER, ENT_QUOTES, 'UTF-8') . '">DROP</abbr>' : '') . '</td>';
        $rows_html .= '</tr>';
    }

    arsort($country_counts);

    $summary       = build_summary($rows_for_summary);
    $matches_total = $summary['total'];
    $all_unresolved = $matches_total === 0 && !empty($no_result_ips);

    $html = $section_open;

    if ($notice_html !== '') {
        $html .= $notice_html;
    }

    if ($summary['line'] !== '') {
        // Structured per-fact markup (not just the plain-text 'line') so mobile
        // CSS can wrap one fact per line and show only the top ASN (D15).
        $html .= '<div id="lookup-summary" class="lookup-summary" role="status">';
        $html .= '<span class="lookup-summary-fact lookup-summary-total">'
            . number_format($summary['total']) . ' IP' . ($summary['total'] === 1 ? '' : 's') . ' looked up</span>';
        foreach ($summary['categories'] as $cat) {
            $html .= '<span class="lookup-summary-fact lookup-summary-category lookup-summary-category--' . htmlspecialchars($cat['key'], ENT_QUOTES, 'UTF-8') . '">'
                . htmlspecialchars($cat['label'], ENT_QUOTES, 'UTF-8') . ' ' . number_format($cat['count']) . ' (' . $cat['pct'] . '%)</span>';
        }
        if (!empty($summary['top_asns'])) {
            $html .= '<span class="lookup-summary-fact lookup-summary-asns">top ASNs: ';
            foreach ($summary['top_asns'] as $i => $a) {
                $asn_text = htmlspecialchars(trim($a['asn'] . ' ' . $a['org']), ENT_QUOTES, 'UTF-8');
                if ($i === 0) {
                    $html .= '<span class="lookup-summary-asn lookup-summary-asn--top">' . $asn_text . '</span>';
                } else {
                    $html .= '<span class="lookup-summary-asn-rest">, ' . $asn_text . '</span>';
                }
            }
            $html .= '</span>';
        }
        if ($summary['drop_count'] > 0) {
            $html .= '<span class="lookup-summary-fact lookup-summary-drop">'
                . number_format($summary['drop_count']) . ' in <abbr title="' . htmlspecialchars(DROP_EXPLAINER, ENT_QUOTES, 'UTF-8') . '">Spamhaus DROP</abbr> netblocks</span>';
        }
        $html .= '</div>';
    }

    // --- Filter & Export (above table) ---
    $html .= '<div id="filter-export" role="region" aria-label="Filter and Export">';
    $html .= '<details id="filter-details" open>';
    $html .= '<summary id="filter-summary">Filter &amp; Export &mdash; Showing <span id="filter-count">' . $matches_total . '</span> of <span id="filter-total">' . $matches_total . '</span> IPs</summary>';
    $html .= '<div id="filter-layout">';

    // Left column: action buttons + firewall rules output
    $html .= '<div id="filter-left">';

    $html .= '<div id="action-buttons-primary">';
    $html .= '<button id="download-csv" class="button small">&#8595; Download CSV</button>';
    if (!empty($no_result_ips)) {
        $n = count($no_result_ips);
        $v6_unresolved = 0;
        foreach ($no_result_ips as $u) {
            if (strpos($u, ':') !== false) {
                $v6_unresolved++;
            }
        }
        $suffix = $v6_unresolved > 0 ? ' (' . $v6_unresolved . ' IPv6)' : '';
        $verb = $all_unresolved ? 'Hide ' : 'Show ';
        $html .= '<button id="toggle-unresolved" class="button small alt" data-suffix="' . htmlspecialchars($suffix, ENT_QUOTES, 'UTF-8') . '">' . $verb . $n . ' unresolved IP' . ($n !== 1 ? 's' : '') . $suffix . '</button>';
    }
    $html .= '</div>';

    $html .= '<div id="export-buttons">';
    $html .= '<button class="button small" id="show-iptables">Show iptables rules</button>';
    $html .= '<button class="button small" id="show-ufw">Show ufw rules</button>';
    $html .= '<button class="button small" id="show-nginx">Show nginx block</button>';
    $html .= '</div>';

    $html .= '<div id="rules-iptables" class="rules-block" style="display:none" aria-label="iptables block rules"><button class="button small copy-rules" data-target="rules-iptables-pre">Copy</button><pre id="rules-iptables-pre"></pre></div>';
    $html .= '<div id="rules-ufw"      class="rules-block" style="display:none" aria-label="ufw deny rules"><button class="button small copy-rules" data-target="rules-ufw-pre">Copy</button><pre id="rules-ufw-pre"></pre></div>';
    $html .= '<div id="rules-nginx"    class="rules-block" style="display:none" aria-label="nginx geo block"><button class="button small copy-rules" data-target="rules-nginx-pre">Copy</button><pre id="rules-nginx-pre"></pre></div>';

    $html .= '</div>'; // end #filter-left

    // Right column: filter chips
    $html .= '<div id="filter-right">';

    $category_counts = array_column($summary['categories'], 'count', 'key');
    $html .= '<div id="filter-categories">';
    $html .= '<strong>ASN Categories</strong>';
    foreach (SUMMARY_CATEGORY_LABELS as $cat => $cat_label) {
        if (($category_counts[$cat] ?? 0) === 0) {
            continue;
        }
        $cat_safe = htmlspecialchars($cat, ENT_QUOTES, 'UTF-8');
        $html .= '<label class="cat-' . $cat_safe . '"><input type="checkbox" class="filter-category" value="' . $cat_safe . '" checked><span class="chip-label">' . $cat_label . '</span> <span class="chip-count">(' . $category_counts[$cat] . ')</span></label>';
    }
    $html .= '</div>';

    $html .= '<div id="filter-countries">';
    $html .= '<strong>Countries <span class="chip-hint">&#8679; multi-select</span></strong>';
    $html .= '<div class="filter-chips">';
    foreach ($country_counts as $cc => $count) {
        $cc_safe = htmlspecialchars($cc, ENT_QUOTES, 'UTF-8');
        $html .= '<label><input type="checkbox" class="filter-country" value="' . $cc_safe . '" checked><span class="chip-label">' . $cc_safe . '</span> <span class="chip-count">(' . $count . ')</span></label>';
    }
    $html .= '</div>';
    $html .= '</div>'; // end #filter-countries

    $html .= '</div>'; // end #filter-right
    $html .= '</div>'; // end #filter-layout
    $html .= '</details></div>'; // end #filter-details, #filter-export

    // --- Results table ---
    $html .= '<div class="table-wrapper" style="overflow-x:auto">';

    $html .= '<table id="results-table"><caption style="position:absolute;left:-9999px">Lookup results, one row per IP address</caption><thead><tr>';
    $html .= '<th scope="col">IP</th>';
    $html .= '<th scope="col"><abbr title="Country Code">CC</abbr></th><th scope="col" class="cell-region">State/Province</th><th scope="col" class="cell-city">City</th>';
    $html .= '<th scope="col">ASN</th><th scope="col" class="cell-asn-org">ASN Org</th><th scope="col">Category</th>';
    $html .= '</tr></thead><tbody>';
    $html .= $rows_html;
    $html .= '</tbody>';

    if (!empty($no_result_ips)) {
        $html .= '<tbody id="unresolved-rows"' . ($all_unresolved ? '' : ' style="display:none"') . '>';
        foreach ($no_result_ips as $unresolved_ip) {
            $html .= '<tr><td>' . htmlspecialchars($unresolved_ip, ENT_QUOTES, 'UTF-8') . '</td><td></td><td></td><td></td><td></td><td></td><td></td></tr>';
        }
        $html .= '</tbody>';
    }
    $html .= '</table>';

    // Empty filter state (shown by JS when all rows filtered out)
    $html .= '<p id="empty-filter-msg" style="display:none;text-align:center;padding:1em;opacity:0.7">No IPs match the current filter. Try selecting more categories.</p>';

    $html .= '</div>';

    // --- Summary stats ---
    $submitted = count($ip_freq);
    $html .= '<table id="stats-table" style="font-family:monospace;font-size:0.8em;border-collapse:collapse;margin-top:0.5em;width:auto">';
    $html .= '<tr><td>' . $submitted . '</td><td>IP' . ($submitted !== 1 ? 's' : '') . ' submitted (valid, unique, non-private)</td></tr>';
    $html .= '<tr><td>' . $matches_total . '</td><td>returned geo results</td></tr>';
    if ($filtered_total > 0) {
        $html .= '<tr><td>' . $filtered_total . '</td><td>excluded by country filter</td></tr>';
    }
    $html .= '<tr><td>' . count($no_result_ips) . '</td><td>returned no geo data</td></tr>';
    if ($extracted['v6_count'] > 0) {
        $html .= '<tr><td>' . $extracted['v6_count'] . '</td><td>IPv6 addresses</td></tr>';
    }
    if (!empty($good_countries)) {
        $html .= '<tr><td>&mdash;</td><td>excluded countries: ' . htmlspecialchars(implode(' ', $good_countries), ENT_QUOTES, 'UTF-8') . '</td></tr>';
    }
    $html .= '</table>';

    $html .= $section_close;

    return $html;
}

/**
 * The no-JS POST / lookup (IPG-17): rate-limit, then render_lookup_results().
 * Same per-client-IP limit as api/lookup.php, in its own APCu bucket
 * (LOOKUP_RATE_BUCKET_NOJS; see includes/rate-limit.php for why). When
 * limited, no lookup runs and the results section is a role="alert" notice
 * sent with 429 + Retry-After.
 *
 * Returns status/headers/html instead of sending them so tests can drive it
 * without a real request, APCu or GeoIP database.
 *
 * @param array     $post         like $_POST
 * @param array     $server       like $_SERVER (client IP for the limiter)
 * @param string    $visitor_ip   passed through to render_lookup_results() (R16)
 * @param ?callable $rateLimiter  function(string $clientIp): array{limited:bool,retry_after:int}
 * @param ?callable $render       function(array $post, string $visitor_ip): string,
 *                                defaults to render_lookup_results()
 *
 * @return array{status:int, headers:array<string,string>, html:string}
 */
function handle_nojs_lookup(array $post, array $server, string $visitor_ip = '', ?callable $rateLimiter = null, ?callable $render = null): array
{
    $rateLimiter ??= static fn(string $ip): array => default_lookup_rate_limiter($ip, LOOKUP_RATE_BUCKET_NOJS);
    $render      ??= static fn(array $p, string $v): string => render_lookup_results($p, $v);

    $rate = $rateLimiter(lookup_endpoint_client_ip($server));
    if (!empty($rate['limited'])) {
        $retryAfter = (int)($rate['retry_after'] ?? LOOKUP_RATE_LIMIT_WINDOW_SECONDS);
        return [
            'status'  => 429,
            'headers' => ['Retry-After' => (string)$retryAfter],
            'html'    => '<section id="results" class="block"><div class="section-head"><h2 id="result">Lookup Results</h2><span class="section-tag">01 / Results</span></div>'
                . '<p class="notice" role="alert">Too many lookups from your network. Try again in ' . $retryAfter . 's.</p>'
                . '</section>',
        ];
    }

    return ['status' => 200, 'headers' => [], 'html' => $render($post, $visitor_ip)];
}

// ─────────────────────────────────────────────────────────────────────────
// Page render. Skipped when IP2GEO_SKIP_PAGE_RENDER is defined before this
// file is required, so tests can pull in the functions above (in particular
// render_lookup_results()) without booting a full HTTP page — see
// tests/IndexResultsTest.php.
// ─────────────────────────────────────────────────────────────────────────
if (!defined('IP2GEO_SKIP_PAGE_RENDER')):

header('Cache-Control: ' . ip2geo_index_cache_control());

$visitor_ip_raw = getRealIPAddr();
$visitor_ip     = filter_var($visitor_ip_raw, FILTER_VALIDATE_IP) !== false ? $visitor_ip_raw : '';

// Run the no-JS lookup before any output so a 429 can set its status and
// Retry-After header; the HTML is echoed in place below the form.
$nojs_lookup = null;
if ($_POST) {
    $nojs_lookup = handle_nojs_lookup($_POST, $_SERVER, $visitor_ip);
    http_response_code($nojs_lookup['status']);
    foreach ($nojs_lookup['headers'] as $name => $value) {
        header($name . ': ' . $value);
    }
}

?><!DOCTYPE HTML>
<html lang="en" data-theme="dark">
	<head>
		<!-- R3: strip a #v= share-link payload into memory before the Umami tracker
		     loads, so a missed/ignored data-exclude-hash never leaks it. This inline
		     script is NOT deferred, so it runs at parse time, before the deferred
		     tracker script below executes (deferred scripts run after the document
		     is parsed). See assets/js/workbench.js for what reads window.__ip2geoSharedView. -->
		<script data-cfasync="false">
		(function() {
			var h = window.location.hash;
			if (h.indexOf('#v=') === 0) {
				window.__ip2geoSharedView = h.slice(3);
				if (window.history && window.history.replaceState) {
					window.history.replaceState(null, '', window.location.pathname + window.location.search);
				}
			}
		})();
		</script>
		<!-- Umami (production only) -->
		<?php if (($_SERVER['HTTP_HOST'] === 'ip2geo.org' || getenv('IP2GEO_E2E_FORCE_UMAMI') === '1')): ?>
		<script data-cfasync="false" defer src="/u/script.js" data-website-id="656d7a15-6282-4079-af1e-b8ed857fba2e" data-domains="ip2geo.org" data-exclude-hash="true"></script>
		<?php endif; ?>
		<title>ip2geo — Bulk IP Lookup for Raw Logs, Free</title>
		<meta charset="utf-8" />
		<meta name="description" content="Paste any log and pull out up to 10,000 IPv4 and IPv6 addresses. Filter by country, ASN and category. Free, no signup." />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<meta property="og:title" content="ip2geo · Bulk IP lookup for raw logs" />
		<meta property="og:description" content="Paste up to 10,000 IPs from any log. Country, ASN and category. Free, no signup." />
		<meta property="og:image" content="https://ip2geo.org/assets/images/og-card.png" />
		<meta property="og:image:width" content="1200" />
		<meta property="og:image:height" content="630" />
		<meta property="og:url" content="https://ip2geo.org/" />
		<meta property="og:type" content="website" />
		<meta name="twitter:card" content="summary_large_image" />
		<link rel="preconnect" href="https://fonts.bunny.net" crossorigin>
		<link rel="stylesheet" href="https://fonts.bunny.net/css?family=geist:400,500,700,900|geist-mono:400,500&display=swap">
		<link rel="stylesheet" href="assets/css/v4.css?v=<?php echo APP_VERSION; ?>" />
		<link rel="stylesheet" href="assets/css/ip2geo-print.css?v=<?php echo APP_VERSION; ?>" media="print" />
		<link rel="icon" href="/favicon.ico" />
		<script data-cfasync="false">
		// Apply theme before paint to avoid a flash. An explicit saved choice wins;
		// otherwise follow the OS setting (prefers-color-scheme). Falls back to the
		// dark data-theme on <html> only if JS is off.
		(function() {
			try {
				var t = localStorage.getItem('ip2geo-theme');
				if (t !== 'light' && t !== 'dark') {
					t = (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
				}
				document.documentElement.setAttribute('data-theme', t);
			} catch (_) {}
		})();
		</script>
	</head>
	<body>

		<!-- Top nav -->
		<header class="nav" role="banner">
			<div class="nav-inner">
				<a href="/" class="wordmark" aria-label="ip2geo home">ip2geo</a>
				<nav class="nav-links" aria-label="primary">
					<a href="#lookup">Lookup</a>
					<a href="#contribute">Contact</a>
					<a href="#about">About</a>
					<button class="theme-toggle" id="themeToggle" type="button" aria-label="Toggle color theme">
						<svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
						<svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
					</button>
				</nav>
			</div>
		</header>

		<main>

			<!-- Hero / Lookup -->
			<section class="hero" id="lookup" aria-labelledby="lookup-h">
				<div class="section-head">
					<h1 id="lookup-h">ip2geo Lookup</h1>
					<span class="section-tag">01 / Lookup</span>
				</div>

				<p class="lead">
					Paste any log, netstat output or ticket text. Up to 10,000 IPs, IPv4 and IPv6, pulled out and looked up in seconds.
				</p>

				<form class="lookup-form" action="#results" method="post" name="ip_entry" id="iplookup">
					<label for="message" class="sr-only" style="position:absolute;left:-9999px">Text containing IP addresses</label>
					<div class="form-grid">
						<textarea class="ip-textarea" name="ip_list" id="message" rows="6" spellcheck="false" placeholder="Paste a log, netstat output or any text with IP addresses… or try a sample log with the link below."><?php
if (isset($_POST['ip_list'])) {
	echo htmlspecialchars($_POST['ip_list'], ENT_QUOTES, 'UTF-8');
}
		?></textarea>

						<div class="form-side">
							<div class="field">
								<label for="countries_filter">Countries to exclude</label>
								<input type="text" id="countries_filter" name="countries_filter" placeholder="e.g. US CA GB" value="<?php if (isset($_POST['countries_filter'])) { echo htmlspecialchars(strtoupper($_POST['countries_filter']), ENT_QUOTES, 'UTF-8'); } ?>" />
								<div class="field-hint"><a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2" target="_blank" rel="noopener noreferrer">2-letter ISO codes</a> separated by spaces. Use to filter out non-suspicious IPs.</div>
							</div>

							<div class="actions">
								<input type="submit" class="button submit" value="Look Up IP Addresses" />
								<!-- Opt-out toggle for recent-lookups (default on; localStorage only).
								     Lives under the submit button: discoverable but unobtrusive. -->
								<div id="rl-optin-row" class="opt-in-toggle" hidden>
									<label class="opt-in" title="Stored in your browser only. Never sent to our server.">
										<input type="checkbox" id="rl-optin" name="rl-optin">
										Save recent lookups <span class="muted-tag">(this browser only)</span>
									</label>
								</div>
							</div>
						</div>
					</div>
				</form>

				<p class="sample-log-link"><a href="#" id="try-sample-log" data-sample-url="assets/sample-fail2ban.txt" data-visitor-ip="<?php echo htmlspecialchars($visitor_ip, ENT_QUOTES, 'UTF-8'); ?>">Try a sample log <span aria-hidden="true">→</span></a></p>

				<!-- Recent lookups widget — rendered by ip2geo-app.js when opt-in is on + list is nonempty.
				     Sits below the form so the asymmetric hero stays tight; surfaces returning users'
				     prior lookups right where they'd reach next. -->
				<div id="recent-lookups" hidden>
					<div id="recent-lookups-header">
						<h3>Recent lookups <small>(this browser only)</small></h3>
						<button type="button" id="recent-lookups-clear" class="button small">Clear</button>
					</div>
					<ul id="recent-lookups-list"></ul>
				</div>
			</section>

<?php if ($nojs_lookup !== null): ?>
<?php echo $nojs_lookup['html']; ?>
<?php endif; ?>

			<!-- Phase 2 workbench mount point (design doc: "Progressive enhancement").
			     Built and shown by assets/js/workbench.js; the server-rendered
			     #results above (render_lookup_results()) is the no-JS fallback and
			     stays untouched. Hidden by default; JS shows it and hides #results
			     once a browser-side lookup succeeds. -->
			<section id="workbench-root" class="block" hidden aria-labelledby="workbench-h">
				<div class="section-head">
					<h2 id="workbench-h">Lookup Results</h2>
					<span class="section-tag">01 / Results</span>
				</div>
				<div class="wb-toast-host"></div>
				<p class="wb-recipient-banner" hidden role="status"></p>
				<div class="wb-paste-bar"></div>
				<div class="wb-state" hidden></div>
				<div class="wb-body" hidden>
					<div class="wb-summary lookup-summary" role="status"></div>
					<div class="wb-export-hint" hidden></div>
					<div class="wb-filters">
						<div class="wb-chips-row"><div class="wb-chips-category"></div></div>
						<div class="wb-chips-row"><div class="wb-chips-country"></div></div>
					</div>
					<div class="wb-toolbar">
						<div class="wb-export"></div>
						<button type="button" class="button small wb-share-btn">Copy share link</button>
						<button type="button" class="button small wb-share-download" hidden>Download view file</button>
						<button type="button" class="button small alt wb-toggle-unresolved" hidden>Show unresolved</button>
						<span class="wb-spacer"></span>
						<span class="wb-shown-count"></span>
						<button type="button" class="wb-clear-filters" hidden>Clear filters</button>
					</div>
					<div class="table-wrapper" style="overflow-x:auto">
						<table class="wb-table" id="wb-results-table">
							<caption style="position:absolute;left:-9999px">Lookup results, one row per IP address</caption>
							<thead><tr>
								<th scope="col" data-key="ip">IP</th>
								<th scope="col" data-key="country"><abbr title="Country Code">CC</abbr></th>
								<th scope="col" data-key="region" class="cell-region">State/Province</th>
								<th scope="col" data-key="city" class="cell-city">City</th>
								<th scope="col" data-key="asn">ASN</th>
								<th scope="col" data-key="asnOrg" class="cell-asn-org">ASN Org</th>
								<th scope="col" data-key="category">Category</th>
								<th scope="col" data-key="hits" aria-sort="descending" style="text-align:right">Hits</th>
							</tr></thead>
							<tbody></tbody>
							<tbody class="wb-unresolved-rows" hidden></tbody>
						</table>
						<div class="wb-table-sentinel"></div>
					</div>
					<p class="wb-empty-filter" hidden style="text-align:center;padding:1em;opacity:0.7">No IPs match the current filter. Try selecting more categories.</p>
				</div>
			</section>

			<!-- Contact / Contribute -->
			<section class="block" id="contribute" aria-labelledby="contact-h">
				<div class="section-head">
					<h2 id="contact-h">Contact / Contribute</h2>
					<span class="section-tag">02 / Contact</span>
				</div>

				<div class="block-body" style="margin-bottom:32px">
					<p>ip2geo.org is maintained and run by me, Josh. Hi. If this tool was helpful, feel free to say hello, or help cover hosting costs if the free tools saved the day.</p>
				</div>

				<div class="about-grid">
					<div>
						<h3>Social</h3>
						<p>
							<a href="https://joshgister.com/" target="_blank" rel="noopener">Personal site</a><br>
							<a href="https://www.linkedin.com/in/joshgister/" target="_blank" rel="noopener">LinkedIn</a><br>
							<a rel="me noopener" href="https://ioc.exchange/@joshgister" target="_blank">Mastodon</a>
						</p>
					</div>
					<div>
						<h3>Donate</h3>
						<p><a href="https://www.buymeacoffee.com/ip2geo" target="_blank" rel="noopener">Buy me a coffee &rarr;</a></p>
					</div>
				</div>
			</section>


			<!-- About -->
			<section class="block" id="about" aria-labelledby="about-h">
				<div class="section-head">
					<h2 id="about-h">About ip2geo.org</h2>
					<span class="section-tag">03 / About</span>
				</div>

				<div class="about-prose">
					<h3>Why This Exists</h3>
					<p>Ever been on the wrong end of a distributed probe hammering away at your email server, SSH port, or some other exposed service? It's chaos. Logs scroll by like a waterfall, and your tools? They're powerful, sure &mdash; but not exactly friendly when you're trying to make sense of hundreds of connections in real time.</p>

					<h3>The Problem</h3>
					<p>You run a CLI command, grab the output, and paste it into your favorite text editor. You start cleaning it up, extracting IPs manually, only to hit a wall: now you're supposed to copy-paste those addresses into a web form. One by one. Seriously?</p>
					<p>When you're facing a flood of suspicious traffic, that's just not going to cut it.</p>

					<h3>The Fix</h3>
					<p>I was maintaining an aging email system with no password policies and no support &mdash; a perfect storm for account compromises. With no time or budget to overhaul it, I built this tool instead.</p>
					<p>ip2geo.org lets you paste raw output from tools like <code>netstat</code>, <code>fail2ban</code>, or anything else that spits out IPs. It automatically extracts valid IPv4 and IPv6 addresses, runs a fast geolocation lookup, and gives you clean, actionable data &mdash; instantly. With one glance, I could see login attempts from every corner of the globe and quickly block entire botnets.</p>

					<h3>What It's Grown Into</h3>
					<p>The free lookup is still here, and it's the whole tool. Paste a log, get a summary line up front &mdash; how much of it is cloud infrastructure, scanning traffic, VPN/proxy exits, or plain residential, plus which ASNs show up the most and how many IPs sit in Spamhaus's DROP list of known-hijacked netblocks.</p>

					<h3>How It Works</h3>
					<p>Paste any block of text. ip2geo.org scans it for IPv4 and IPv6 addresses, checks them against a geolocation database, and returns results you can filter by country or infrastructure category &mdash; scanning ranges, cloud exit nodes, VPN and proxy infrastructure, or residential traffic. Want to only see scanning infrastructure hits from outside the US? Done. Focus only on what matters.</p>

					<h3>Why It's Free</h3>
					<p>This tool was built using free and open-source resources, and it's free because I wish something like this had existed when I needed it most. If it helps you too, consider <a href="https://www.buymeacoffee.com/ip2geo" target="_blank" rel="noopener">buying me a coffee</a> or tossing a few bucks toward hosting costs.</p>
				</div>
			</section>

		</main>

		<?php require __DIR__ . '/includes/footer.php'; ?>

		<!-- Toast container for recent-lookups undo affordance (managed by ip2geo-app.js) -->
		<div id="rl-toast" role="status" aria-live="polite" hidden>
			<span id="rl-toast-msg"></span>
			<button type="button" id="rl-toast-undo">Undo</button>
		</div>

		<!-- Theme toggle -->
		<script data-cfasync="false">
		(function() {
			var btn = document.getElementById('themeToggle');
			if (!btn) return;
			btn.addEventListener('click', function() {
				var root = document.documentElement;
				var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
				root.setAttribute('data-theme', next);
				try { localStorage.setItem('ip2geo-theme', next); } catch (_) {}
			});
		})();
		</script>

		<!-- Smooth in-page anchor scroll (fixed ~500ms regardless of distance) -->
		<script data-cfasync="false">
		(function() {
			var DURATION = 500;
			var OFFSET = 72;
			var reduced = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
			function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }
			function scrollTo(targetY) {
				if (reduced) { window.scrollTo(0, targetY); return; }
				var startY = window.pageYOffset;
				var dy = targetY - startY;
				if (dy === 0) return;
				var t0 = performance.now();
				function step(now) {
					var p = Math.min(1, (now - t0) / DURATION);
					window.scrollTo(0, startY + dy * easeOutCubic(p));
					if (p < 1) requestAnimationFrame(step);
				}
				requestAnimationFrame(step);
			}
			document.addEventListener('click', function(e) {
				var a = e.target.closest && e.target.closest('a[href^="#"]');
				if (!a) return;
				var hash = a.getAttribute('href');
				if (!hash || hash === '#') return;
				var target = document.getElementById(hash.slice(1));
				if (!target) return;
				e.preventDefault();
				var y = target.getBoundingClientRect().top + window.pageYOffset - OFFSET;
				scrollTo(y);
				history.replaceState(null, '', hash);
			});
		})();
		</script>

		<!-- Shared IP extraction (browser mirror of includes/extract.php's extract_ips()).
		     Loaded before ip2geo-app.js and before the inline overlay script below, both
		     of which call window.extractIps(). -->
		<script data-cfasync="false" src="assets/js/extract-ips.js?v=<?php echo APP_VERSION; ?>"></script>

		<!-- Scripts -->
		<script data-cfasync="false">
		(function() {
			var form = document.getElementById('iplookup');
			if (!form) return;

			// A prior AJAX layer used to own the submit button's click here,
			// fetching a server-rendered HTML fragment (FormData POST back to
			// index.php, re-injecting the #results it got back). The Phase 2
			// workbench (assets/js/workbench.js, wired in the bootstrap script
			// below) replaces that: it intercepts the form's `submit` event
			// directly, extracts IPs client-side, and POSTs JSON to
			// /api/lookup.php in one request instead of re-rendering server HTML.
			// Keeping both would double-handle every click — this file no longer
			// attaches anything to the submit button; the plain, unintercepted
			// form POST (render_lookup_results()) remains the no-JS fallback
			// exactly as before.

		// CSV download (delegated — works after AJAX injection)
		document.addEventListener('click', function(e) {
			if (e.target.id !== 'download-csv') return;
			try { umami.track('download_csv'); } catch(_) {}
			var bom = '﻿';
			var headers = ['IP','CC','State/Province','City','ASN','ASN Org','Category'];
			var rows = [headers];
			document.querySelectorAll('#results-table tbody tr').forEach(function(tr) {
				if (tr.parentElement.style.display === 'none') return;
				if (tr.classList.contains('row-hidden')) return;
				var row = [];
				tr.querySelectorAll('td').forEach(function(td) {
					// Strip UI-only affordances so the CSV gets clean data: the
					// "(you)" / "DROP" tags, and (mobile) the truncated IPv6 display
					// — .ip-full (the untruncated address) is what should survive.
					var clone = td.cloneNode(true);
					clone.querySelectorAll('.you-tag, .drop-tag, .ip-truncated').forEach(function(el) { el.remove(); });
					row.push(window.ip2geoExport.csvEscape(clone.textContent.trim()));
				});
				rows.push(row);
			});
			var csv = bom + rows.map(function(r) { return r.join(','); }).join('\r\n');
			var a = document.createElement('a');
			a.href = URL.createObjectURL(new Blob([csv], {type: 'text/csv;charset=utf-8;'}));
			a.download = 'ip2geo-results.csv';
			a.click();
			URL.revokeObjectURL(a.href);
		});

		// Toggle unresolved rows — handler moved to ip2geo-app.js so it can call applyFilters()

		})();
		</script>
		<script data-cfasync="false" src="assets/js/ip2geo-app.js?v=<?php echo APP_VERSION; ?>"></script>
		<script data-cfasync="false" src="assets/js/abbr-popover.js?v=<?php echo APP_VERSION; ?>"></script>

		<!-- Phase 2 workbench: pure modules, then the DOM orchestration layer, then the bootstrap. -->
		<script data-cfasync="false" src="assets/js/filters.js?v=<?php echo APP_VERSION; ?>"></script>
		<script data-cfasync="false" src="assets/js/export-templates.js?v=<?php echo APP_VERSION; ?>"></script>
		<script data-cfasync="false" src="assets/js/summary.js?v=<?php echo APP_VERSION; ?>"></script>
		<script data-cfasync="false" src="assets/js/share-link.js?v=<?php echo APP_VERSION; ?>"></script>
		<script data-cfasync="false" src="assets/js/workbench.js?v=<?php echo APP_VERSION; ?>"></script>
		<script data-cfasync="false">
		(function () {
			var root = document.getElementById('workbench-root');
			var oldResults = document.getElementById('results');
			var form = document.getElementById('iplookup');
			var textarea = document.getElementById('message');
			if (!root || !form || !textarea || !window.ip2geoWorkbench) return;

			var mounted = window.ip2geoWorkbench.mount(root, form, textarea);
			if (!mounted) return; // extractIps missing: let the form submit normally (no-JS fallback)

			function hideOldResults() {
				if (oldResults) oldResults.style.display = 'none';
			}

			// Wrap startLookup so a successful JS lookup hides the PHP-rendered
			// #results (if the page happens to have one, e.g. a JS-disabled-then-
			// re-enabled reload) and scrolls to the workbench, matching the old
			// form's action="#results" behavior.
			var realStart = mounted.startLookup;
			mounted.startLookup = function (text) {
				return realStart(text).then(function (ok) {
					if (ok) {
						hideOldResults();
						root.scrollIntoView({ block: 'start' });
					}
					return ok;
				});
			};

			// D8 recipient path: a #v= payload captured by R3's inline script
			// (must run before this, and before the Umami tracker) before we ever
			// get here.
			if (window.__ip2geoSharedView) {
				var banner = root.querySelector('.wb-recipient-banner');
				window.ip2geoWorkbench.mountSharedView(root, window.__ip2geoSharedView, function (text) {
					if (banner) {
						banner.hidden = false;
						banner.textContent = text + ' ';
						var saveBtn = document.createElement('button');
						saveBtn.type = 'button';
						saveBtn.className = 'button small';
						saveBtn.textContent = 'Save as view file';
						saveBtn.addEventListener('click', function () {
							// Re-derive the view file from the decoded payload via the share-link module.
							var decoded = window.ip2geoShareLink.decodeShareState(window.__ip2geoSharedView);
							if (!decoded) return;
							var json = window.ip2geoShareLink.buildViewFile(decoded);
							var a = document.createElement('a');
							a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
							a.download = 'view.ip2geo.json';
							a.click();
							URL.revokeObjectURL(a.href);
						});
						banner.appendChild(saveBtn);
					}
				}).then(function (ok) {
					if (ok) hideOldResults();
				});
			}

			// D12: an old #results bookmark with no lookup on the page yet.
			if (window.location.hash === '#results' && !oldResults && root.hidden) {
				textarea.focus();
				var hint = document.createElement('p');
				hint.className = 'notice';
				hint.setAttribute('role', 'status');
				hint.textContent = 'Paste a log to see results.';
				form.parentNode.insertBefore(hint, form.nextSibling);
			}
		})();
		</script>

	</body>
</html>
<?php endif; // IP2GEO_SKIP_PAGE_RENDER ?>
