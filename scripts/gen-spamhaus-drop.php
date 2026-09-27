<?php
/**
 * Generate spamhaus_drop_data.php from the Spamhaus combined DROP list.
 *
 * Reads the DROP feed as NDJSON on stdin (one JSON object per line, e.g.
 *   {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
 * plus a trailing {"type":"metadata",...} line with no "cidr"), converts each
 * CIDR to an inclusive [start_int, end_int] unsigned-32-bit IPv4 range, sorts
 * ascending by start, merges overlapping/adjacent ranges, and writes a complete,
 * machine-owned PHP data file to stdout.
 *
 * Usage (also what .github/workflows/sync-spamhaus-drop.yml runs):
 *   curl -sf https://www.spamhaus.org/drop/drop_v4.json \
 *     | php scripts/gen-spamhaus-drop.php > spamhaus_drop_data.php
 *
 * Exit non-zero (without emitting a file) on empty/garbage input so a failed
 * Spamhaus fetch never empties the committed data file. The same applies when the
 * feed's metadata record (copyright, timestamp, terms) is missing or malformed:
 * the file header carries that attribution verbatim, so no file is written
 * without it. The lookup that consumes this output is ip_in_spamhaus_drop() in
 * report_functions.php.
 *
 * spamhaus_feed_metadata() and spamhaus_feed_header_lines() also serve the
 * ASN-DROP feed: .github/workflows/sync-spamhaus.yml calls them to write the
 * same attribution into the auto-sync block of asn_classification.php, and
 * spamhaus_asndrop_asns() / spamhaus_asndrop_block_is_safe() to extract the
 * ASNs and check the block it writes.
 */

/**
 * Pull the attribution out of a Spamhaus NDJSON feed's {"type":"metadata",...}
 * record, e.g.
 *   {"type":"metadata","timestamp":1790518442,"size":104402,"records":1711,
 *    "copyright":"(c) 2026 The Spamhaus Project SLU",
 *    "terms":"https://www.spamhaus.org/drop/terms/"}
 *
 * The values are written verbatim into a PHP line comment, so anything that
 * could end that comment or confuse the files it lands in is refused rather
 * than cleaned up. Each value must be 1-200 characters of letters, numbers,
 * punctuation, symbols and plain spaces, which rules out control characters (a
 * newline would put the rest of the value outside the comment), bidi overrides,
 * zero-width and line/paragraph separators, and invalid UTF-8. On top of that:
 * no "?>" (it closes PHP mode even inside a // comment), no "AUTO-SYNC" (a copy
 * of the END marker in the ASN-DROP block header would make the next
 * sync-spamhaus.yml run stop there and orphan the old block), and terms must be
 * an https:// URL with no whitespace.
 *
 * @param string $ndjson  Raw NDJSON feed contents (DROP or ASN-DROP).
 * @return array{copyright:string,timestamp:int,terms:string}|null  null when the
 *         feed has no metadata record, or its copyright/timestamp/terms are
 *         missing or unsafe to write into the header.
 */
function spamhaus_feed_metadata(string $ndjson): ?array {
    foreach (explode("\n", $ndjson) as $line) {
        $rec = json_decode(trim($line), true);
        if (!is_array($rec) || ($rec['type'] ?? null) !== 'metadata') {
            continue;
        }
        $copyright = $rec['copyright'] ?? null;
        $timestamp = $rec['timestamp'] ?? null;
        $terms     = $rec['terms'] ?? null;
        if (!is_int($timestamp) || $timestamp <= 0) {
            return null;
        }
        foreach ([$copyright, $terms] as $value) {
            if (!is_string($value) || trim($value) === ''
                || preg_match('/^[\p{L}\p{N}\p{P}\p{S} ]{1,200}$/u', $value) !== 1
                || str_contains($value, '?>') || str_contains($value, 'AUTO-SYNC')
            ) {
                return null;
            }
        }
        if (preg_match('~^https://\S+$~', $terms) !== 1) {
            return null;
        }
        return ['copyright' => $copyright, 'timestamp' => $timestamp, 'terms' => $terms];
    }
    return null;
}

/**
 * The attribution lines for a data file header, without the comment prefix:
 * the feed's copyright and terms verbatim, and its timestamp as the raw epoch
 * plus ISO-8601 UTC.
 *
 * @param array{copyright:string,timestamp:int,terms:string} $meta  From spamhaus_feed_metadata().
 * @return list<string>
 */
function spamhaus_feed_header_lines(array $meta): array {
    return [
        "Copyright: {$meta['copyright']}",
        "Terms: {$meta['terms']}",
        "Feed timestamp: {$meta['timestamp']} (" . gmdate('Y-m-d\\TH:i:s\\Z', $meta['timestamp']) . ')',
    ];
}

/**
 * The ASNs listed in the ASN-DROP NDJSON feed, e.g.
 *   {"asn":245,"rir":"arin","domain":"planningresearchcorp.com","cc":"US","asname":"PRC-AS"}
 * as sorted, de-duplicated "AS245" strings.
 *
 * sync-spamhaus.yml writes each one into asn_classification.php as
 * `'AS245' => 'scanning',`, i.e. into PHP source that auto-promote ships to
 * production without review. So the whole feed is refused, not cleaned up, if
 * any line is not JSON or any record's asn is not a JSON integer in
 * 1..4294967295: a string asn such as "1' => x, '" would otherwise become code.
 * Records without an asn (the metadata record) are skipped.
 *
 * @param string $ndjson  Raw ASN-DROP NDJSON feed contents.
 * @return list<string>|null  null when the feed has no ASNs or any record is unusable.
 */
function spamhaus_asndrop_asns(string $ndjson): ?array {
    $asns = [];
    foreach (explode("\n", $ndjson) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $rec = json_decode($line, true);
        if (!is_array($rec)) {
            return null;
        }
        if (!array_key_exists('asn', $rec) || $rec['asn'] === null) {
            continue;
        }
        $asn = $rec['asn'];
        if (!is_int($asn) || $asn < 1 || $asn > 4294967295) {
            return null;
        }
        $asns[$asn] = true;
    }
    if (!$asns) {
        return null;
    }
    ksort($asns);
    return array_map(static fn(int $asn): string => "AS{$asn}", array_keys($asns));
}

/**
 * Whether the ASN-DROP auto-sync block in asn_classification.php holds only
 * comments and `'AS<digits>' => 'scanning',` entries. sync-spamhaus.yml checks
 * this after writing the block and before php -l, which checks syntax only: a
 * line that parses but runs code must stop the sync before it is committed.
 *
 * Requires exactly one BEGIN and one END marker, BEGIN first. Every line
 * between them must be `    // ` plus a comment with no "?>" and no control
 * characters (PHP also ends a // comment at \r), or
 * `    'AS<1-10 digits>' => 'scanning',`.
 *
 * @param string $src  Full contents of asn_classification.php.
 */
function spamhaus_asndrop_block_is_safe(string $src): bool {
    $begin = '    // --- BEGIN AUTO-SYNC SPAMHAUS ASN-DROP (do not hand-edit) ---';
    $end   = '    // --- END AUTO-SYNC SPAMHAUS ASN-DROP ---';
    $lines = explode("\n", $src);
    $b = array_keys($lines, $begin, true);
    $e = array_keys($lines, $end, true);
    if (count($b) !== 1 || count($e) !== 1 || $e[0] <= $b[0]
        || substr_count($src, 'AUTO-SYNC SPAMHAUS ASN-DROP') !== 2
    ) {
        return false;
    }
    for ($i = $b[0] + 1; $i < $e[0]; $i++) {
        $line = $lines[$i];
        if (preg_match("~^    'AS[0-9]{1,10}' => 'scanning',$~D", $line) === 1) {
            continue;
        }
        if (str_starts_with($line, '    // ') && !str_contains($line, '?>')
            && preg_match('/[\x00-\x1F\x7F]/', $line) !== 1
        ) {
            continue;
        }
        return false;
    }
    return true;
}

/**
 * Parse the DROP NDJSON into a list of un-merged per-CIDR records, each
 * [start_int, end_int, "cidr"], sorted ascending by start. Pulled out as a pure
 * function so both the merged hot-path array and the report's per-CIDR labels are
 * derived from one parse, and so it can be unit-tested without I/O.
 *
 * @param string $ndjson  Raw NDJSON feed contents.
 * @return array<int, array{0:int,1:int,2:string}>  Sorted original CIDR records.
 */
function spamhaus_drop_cidrs_from_ndjson(string $ndjson): array {
    $cidrs = [];
    foreach (explode("\n", $ndjson) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $rec = json_decode($line, true);
        // Skip the metadata header/footer line and anything without a cidr.
        if (!is_array($rec) || !isset($rec['cidr']) || !is_string($rec['cidr'])) {
            continue;
        }
        $cidr = $rec['cidr'];
        if (strpos($cidr, '/') === false) {
            continue;
        }
        [$net, $prefix] = explode('/', $cidr, 2);
        $prefix = (int) $prefix;
        $base   = ip2long($net);
        if ($base === false || $prefix < 0 || $prefix > 32) {
            continue; // not a valid IPv4 CIDR (DROPv6 is out of scope)
        }
        // Unsigned base via %u; 64-bit PHP holds the full 0..2^32-1 range.
        $start = (int) sprintf('%u', $base);
        $size  = 1 << (32 - $prefix);            // /0 => 2^32, fits in 64-bit int
        $end   = $start + $size - 1;
        $cidrs[] = [$start, $end, $cidr];
    }

    // Sort ascending by start (then by end so a containing block precedes the
    // blocks it covers — handy for the report's most-specific-on-overlap search).
    usort($cidrs, static fn($a, $b) => $a[0] <=> $b[0] ?: $a[1] <=> $b[1]);

    return $cidrs;
}

/**
 * Parse the DROP NDJSON into a sorted, merged list of [start, end] int ranges.
 * Pulled out as a pure function so it can be unit-tested without I/O.
 *
 * @param string $ndjson  Raw NDJSON feed contents.
 * @return array<int, array{0:int,1:int}>  Sorted, merged inclusive ranges.
 */
function spamhaus_drop_ranges_from_ndjson(string $ndjson): array {
    $cidrs = spamhaus_drop_cidrs_from_ndjson($ndjson);
    if (!$cidrs) {
        return [];
    }

    // Already sorted ascending by start; merge overlapping or adjacent ranges so
    // the consumer's binary search can assume a disjoint, sorted list.
    $merged = [];
    [$curStart, $curEnd] = $cidrs[0];
    $count = count($cidrs);
    for ($i = 1; $i < $count; $i++) {
        [$s, $e] = $cidrs[$i];
        if ($s <= $curEnd + 1) {            // overlapping or directly adjacent
            if ($e > $curEnd) {
                $curEnd = $e;
            }
        } else {
            $merged[] = [$curStart, $curEnd];
            $curStart = $s;
            $curEnd   = $e;
        }
    }
    $merged[] = [$curStart, $curEnd];

    return $merged;
}

/**
 * Render the data file body from the merged ranges + the un-merged CIDR list.
 *
 * Emits two globals: $spamhaus_drop_ranges (merged, the hot-path membership
 * array — byte-identical to the pre-CIDR-array format) and $spamhaus_drop_cidrs
 * (the original per-CIDR records, so the report can name + block the specific
 * netblock the merge threw away).
 *
 * @param array<int, array{0:int,1:int}>        $ranges  Merged inclusive ranges.
 * @param array<int, array{0:int,1:int,string}> $cidrs   Un-merged [start,end,cidr].
 * @param array{copyright:string,timestamp:int,terms:string} $meta  From spamhaus_feed_metadata().
 */
function spamhaus_drop_render(array $ranges, array $cidrs, array $meta): string {
    $today = gmdate('Y-m-d');
    $out  = "<?php\n";
    $out .= "// AUTO-GENERATED by .github/workflows/sync-spamhaus-drop.yml — do not hand-edit.\n";
    $out .= "// Source: https://www.spamhaus.org/drop/drop_v4.json (combined DROP, includes former EDROP)\n";
    foreach (spamhaus_feed_header_lines($meta) as $line) {
        $out .= "// {$line}\n";
    }
    $out .= "// Spamhaus data, not covered by this repository's license; see NOTICE.\n";
    $out .= "// Last sync: {$today}\n";
    $out .= "//\n";
    $out .= "// Sorted ascending by start_int, non-overlapping (merged on generation).\n";
    $out .= "// One [start_int, end_int] inclusive unsigned-32-bit IPv4 pair per listed CIDR.\n";
    $out .= "// Consumed by ip_in_spamhaus_drop() in report_functions.php (binary search).\n";
    $out .= "global \$spamhaus_drop_ranges;\n";
    $out .= "\$spamhaus_drop_ranges = [\n";
    foreach ($ranges as $r) {
        $out .= "    [{$r[0]}, {$r[1]}],\n";
    }
    $out .= "];\n";
    $out .= "\n";
    $out .= "// Un-merged original CIDRs as [start_int, end_int, \"cidr\"], sorted ascending by\n";
    $out .= "// start. The merge above throws away CIDR boundaries; the threat report needs to\n";
    $out .= "// name + block the specific netblock, so the originals are retained here.\n";
    $out .= "// Consumed by spamhaus_drop_cidr_for_ip() in report_functions.php (binary search).\n";
    $out .= "global \$spamhaus_drop_cidrs;\n";
    $out .= "\$spamhaus_drop_cidrs = [\n";
    foreach ($cidrs as $c) {
        $out .= "    [{$c[0]}, {$c[1]}, " . var_export($c[2], true) . "],\n";
    }
    $out .= "];\n";
    return $out;
}

// --- CLI entry point ---------------------------------------------------------
// Only run when executed directly (curl ... | php scripts/gen-spamhaus-drop.php).
// When required from the test suite this is skipped, so the functions above are
// importable without consuming STDIN.
if (PHP_SAPI === 'cli'
    && isset($_SERVER['SCRIPT_FILENAME'])
    && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)
) {
    $ndjson = stream_get_contents(STDIN);
    if ($ndjson === false || trim($ndjson) === '') {
        fwrite(STDERR, "gen-spamhaus-drop: empty input — refusing to emit an empty data file.\n");
        exit(1);
    }

    $cidrs  = spamhaus_drop_cidrs_from_ndjson($ndjson);
    $ranges = spamhaus_drop_ranges_from_ndjson($ndjson);
    if (!$ranges) {
        fwrite(STDERR, "gen-spamhaus-drop: parsed 0 CIDR ranges — aborting (bad feed?).\n");
        exit(1);
    }

    $meta = spamhaus_feed_metadata($ndjson);
    if ($meta === null) {
        fwrite(STDERR, "gen-spamhaus-drop: no usable metadata record (copyright, timestamp, terms) — aborting.\n");
        exit(1);
    }

    fwrite(STDERR, 'gen-spamhaus-drop: ' . count($ranges) . ' merged ranges, '
        . count($cidrs) . " original CIDRs.\n");
    echo spamhaus_drop_render($ranges, $cidrs, $meta);
}
