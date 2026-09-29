<?php
/**
 * Generates <fixture>.full.json for every extraction fixture, by running the
 * real extract_ips() (includes/extract.php) over each *.txt fixture and
 * dumping its complete v4+v6 return value.
 *
 * tests/js/extract-ips.test.js loads these to prove the JS extractor
 * matches the PHP extractor exactly. tests/ExtractIpsTest.php instead
 * compares the IPv4-only projection against the original golden <name>.json
 * files, which were captured from origin/main's inline extraction before
 * this refactor (see the worktree report for how those were produced).
 *
 * Run once, by hand, whenever a fixture or extract_ips() changes:
 *   php tests/fixtures/extract/generate-expected.php
 *
 * The worst-case-2mb fixture is intentionally excluded: it is generated at
 * test time (identically in PHP and JS) rather than committed, and its
 * expected output is asserted by direct comparison in both test suites
 * instead of a stored *.full.json.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../../includes/extract.php';

$dir = __DIR__;
$fixtures = [
    'fail2ban',
    'netstat',
    'nginx-access',
    'mixed-v4v6',
    'cap-12k',
    'private-only',
    'empty',
    'defanged-and-ports',
];

foreach ($fixtures as $name) {
    $text = file_get_contents("$dir/$name.txt");
    $result = extract_ips($text);

    $pairs = [];
    foreach ($result['ips'] as $ip => $count) {
        $pairs[] = [$ip, $count];
    }

    $out = [
        'ips' => $pairs,
        'total_unique' => $result['total_unique'],
        'v6_count' => $result['v6_count'],
    ];

    file_put_contents(
        "$dir/$name.full.json",
        json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
    );
    echo "$name.full.json: " . count($pairs) . " ips, total_unique={$result['total_unique']}, v6_count={$result['v6_count']}\n";
}
