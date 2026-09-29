<?php
/**
 * Shared IP extraction, used by the server and mirrored in
 * assets/js/extract-ips.js for the browser. Locked by golden fixtures in
 * tests/fixtures/extract/ (see tests/ExtractIpsTest.php).
 *
 * IPv4 semantics are byte-for-byte unchanged from the extraction that used
 * to live inline in index.php (~214-226 on origin/main): a strict
 * dotted-quad regex, occurrence counts via array_count_values (first-seen
 * order preserved), a 10,000-unique cap, then private ranges dropped. Two
 * quirks of that original code are preserved here on purpose:
 *
 *   - The cap is applied BEFORE the private-range filter (today's
 *     `array_slice(..., 0, 10000, true)` runs before `array_filter`). A
 *     paste with more than 10,000 unique raw hits can therefore end up
 *     with fewer than 10,000 public IPs if private addresses land inside
 *     the first 10,000 positions. extract_ips() extends this to the
 *     combined v4+v6 cap, but keeps the same "cap first, filter second"
 *     order.
 *   - An IPv6 literal that embeds a dotted IPv4 tail (e.g.
 *     `::ffff:203.0.113.9`) already produces a *separate* IPv4 hit today,
 *     because the IPv4 regex's `\b` matches on the boundary between `:`
 *     and a digit. extract_ips() keeps that IPv4 hit and additionally
 *     recognizes the same text as an IPv6 address — see
 *     tests/fixtures/extract/mixed-v4v6.txt.
 *
 * IPv6 support is new (R15 in the design doc). It uses a two-step scan: a
 * single linear pass over the input collects candidate runs of
 * `[0-9A-Fa-f:.]`, then each candidate is validated strictly (filter_var
 * with FILTER_FLAG_IPV6). No single large IPv6 regex is used anywhere in
 * this file, to avoid catastrophic backtracking on the long hex/colon runs
 * that show up in real logs (MAC addresses, hashes, "::::" noise) — see
 * tests/fixtures/extract/worst-case-2mb, generated at test time.
 */

declare(strict_types=1);

const EXTRACT_IPS_CAP = 10000;

/**
 * IPv4 private/local test — identical to today's test_local() in index.php.
 * (Its regex also carries a dead `|::1$` alternative that can never match a
 * dotted-quad string; kept verbatim for faithfulness, not because it does
 * anything here.)
 */
function extract_ips_is_private_v4(string $ip): bool
{
    return (bool)preg_match('/^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|::1$)/', $ip);
}

/**
 * IPv6 private/local test per the design doc (C3 / R6 accepted scope):
 * ::1, fc00::/7 (unique local), fe80::/10 (link-local), ::ffff:-mapped
 * private IPv4, and 2001:db8::/32 (documentation).
 *
 * $ip must already be a canonical form accepted by inet_pton().
 */
function extract_ips_is_private_v6(string $ip): bool
{
    $bin = @inet_pton($ip);
    if ($bin === false || strlen($bin) !== 16) {
        return false;
    }
    $bytes = array_values(unpack('C16', $bin));

    // ::1 — loopback
    if ($bin === str_repeat("\x00", 15) . "\x01") {
        return true;
    }

    // fc00::/7 — unique local addresses (top 7 bits = 1111110)
    if (($bytes[0] & 0xFE) === 0xFC) {
        return true;
    }

    // fe80::/10 — link-local
    if ($bytes[0] === 0xFE && ($bytes[1] & 0xC0) === 0x80) {
        return true;
    }

    // 2001:db8::/32 — documentation
    if ($bytes[0] === 0x20 && $bytes[1] === 0x01 && $bytes[2] === 0x0D && $bytes[3] === 0xB8) {
        return true;
    }

    // ::ffff:a.b.c.d — IPv4-mapped; private iff the mapped v4 is private
    $isMappedV4 = true;
    for ($i = 0; $i < 10; $i++) {
        if ($bytes[$i] !== 0x00) {
            $isMappedV4 = false;
            break;
        }
    }
    if ($isMappedV4 && $bytes[10] === 0xFF && $bytes[11] === 0xFF) {
        $mapped = sprintf('%d.%d.%d.%d', $bytes[12], $bytes[13], $bytes[14], $bytes[15]);
        return extract_ips_is_private_v4($mapped);
    }

    return false;
}

/** Canonical lowercase-compressed form, matching JS normalizeV6(). */
function extract_ips_normalize_v6(string $ip): ?string
{
    $bin = @inet_pton($ip);
    if ($bin === false || strlen($bin) !== 16) {
        return null;
    }
    $canon = inet_ntop($bin);
    return $canon === false ? null : strtolower($canon);
}

/**
 * Step 2 of the two-step IPv6 scan: strictly validate one candidate token.
 * Returns the normalized address, or null if the token isn't a valid,
 * non-IPv4 IPv6 literal.
 */
function extract_ips_validate_v6_candidate(string $token): ?string
{
    if (filter_var($token, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
        return null;
    }
    return extract_ips_normalize_v6($token);
}

/**
 * extract_ips(): the shared extractor.
 *
 * Returns:
 *   'ips'          => [ip => count, ...] first-seen order across v4+v6 as
 *                     they appear in the text, capped at EXTRACT_IPS_CAP
 *                     unique keys (combined v4+v6, cap applied before the
 *                     private filter — see the file header), then with
 *                     private/local addresses dropped. Filtering the
 *                     result down to IPv4-only keys reproduces today's
 *                     index.php output exactly.
 *   'total_unique' => unique PUBLIC IPs (v4+v6 combined) before the cap.
 *   'v6_count'     => count of IPv6 keys present in the final 'ips' map
 *                     (i.e. after the cap and the private filter).
 */
function extract_ips(string $text): array
{
    // Step 1a: IPv4 — unchanged regex from index.php:214.
    preg_match_all(
        "/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/",
        $text,
        $v4_matches,
        PREG_OFFSET_CAPTURE
    );

    // Step 1b: IPv6 — linear candidate scan (two-step: find, then validate).
    preg_match_all('/[0-9A-Fa-f:.]+/', $text, $v6_candidates, PREG_OFFSET_CAPTURE);

    // Merge both passes into one (offset, type, ip) stream so the combined
    // map preserves true first-seen order across v4 and v6.
    $hits = [];
    foreach ($v4_matches[0] as [$ip, $offset]) {
        $hits[] = [$offset, 'v4', $ip];
    }
    foreach ($v6_candidates[0] as [$token, $offset]) {
        // A candidate must contain a colon to be an IPv6 literal at all;
        // skip the cheap rejects before the strict validation call.
        if (strpos($token, ':') === false) {
            continue;
        }
        $normalized = extract_ips_validate_v6_candidate($token);
        if ($normalized === null) {
            continue;
        }
        $hits[] = [$offset, 'v6', $normalized];
    }

    usort($hits, static fn(array $a, array $b): int => $a[0] <=> $b[0]);

    // Raw, uncapped, unfiltered counts — first-seen order preserved by
    // insertion order (matches array_count_values semantics).
    $raw_freq = [];
    $raw_type = [];
    foreach ($hits as [, $type, $ip]) {
        if (!isset($raw_freq[$ip])) {
            $raw_freq[$ip] = 0;
            $raw_type[$ip] = $type;
        }
        $raw_freq[$ip]++;
    }

    // total_unique: unique PUBLIC ips (v4+v6) before the cap.
    $total_unique = 0;
    foreach ($raw_freq as $ip => $count) {
        $is_private = $raw_type[$ip] === 'v4'
            ? extract_ips_is_private_v4($ip)
            : extract_ips_is_private_v6($ip);
        if (!$is_private) {
            $total_unique++;
        }
    }

    // Cap first (today's order), then filter private — see file header.
    $capped = array_slice($raw_freq, 0, EXTRACT_IPS_CAP, true);

    $ips = [];
    $v6_count = 0;
    foreach ($capped as $ip => $count) {
        $type = $raw_type[$ip];
        $is_private = $type === 'v4'
            ? extract_ips_is_private_v4($ip)
            : extract_ips_is_private_v6($ip);
        if ($is_private) {
            continue;
        }
        $ips[$ip] = $count;
        if ($type === 'v6') {
            $v6_count++;
        }
    }

    return [
        'ips' => $ips,
        'total_unique' => $total_unique,
        'v6_count' => $v6_count,
    ];
}
