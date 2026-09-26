<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../scripts/gen-spamhaus-drop.php'; // spamhaus_drop_render() (CLI entry self-guards)

/**
 * scripts/validate-spamhaus-promote.sh: the last check before sync-spamhaus.yml
 * and sync-spamhaus-drop.yml merge develop into main and deploy it to production
 * unreviewed. It must accept only what the generators write, so anyone who can
 * push to develop cannot ride PHP code to production inside the data files.
 *
 * The committed asn_classification.php and spamhaus_drop_data.php are the
 * passing fixtures; each rejected fixture is one targeted edit to them.
 */
class SpamhausPromoteValidatorTest extends TestCase
{
    private const SCRIPT = __DIR__ . '/../scripts/validate-spamhaus-promote.sh';
    private const ASN_FILE = __DIR__ . '/../asn_classification.php';
    private const DROP_FILE = __DIR__ . '/../spamhaus_drop_data.php';

    private const BEGIN = '    // --- BEGIN AUTO-SYNC SPAMHAUS ASN-DROP (do not hand-edit) ---';
    private const END = '    // --- END AUTO-SYNC SPAMHAUS ASN-DROP ---';

    /** @var list<string> */
    private array $tmpFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tmpFiles as $f) {
            @unlink($f);
        }
    }

    private function tmp(string $contents): string
    {
        $f = tempnam(sys_get_temp_dir(), 'spamhaus-validate-');
        file_put_contents($f, $contents);
        $this->tmpFiles[] = $f;
        return $f;
    }

    /** @return array{0:int,1:string} exit code, stderr */
    private function runScript(string ...$args): array
    {
        $proc = proc_open(
            array_merge(['bash', self::SCRIPT], $args),
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($proc), $stderr];
    }

    /** @return array{0:int,1:string} */
    private function runAsn(string $develop): array
    {
        return $this->runScript('asn', self::ASN_FILE, $this->tmp($develop));
    }

    /** @return array{0:int,1:string} */
    private function runDrop(string $develop): array
    {
        return $this->runScript('drop', $this->tmp($develop));
    }

    /** Insert $lines immediately before the first line equal to $anchor. */
    private static function insertBefore(string $src, string $anchor, string ...$lines): string
    {
        $out = [];
        $done = false;
        foreach (explode("\n", $src) as $l) {
            if (!$done && $l === $anchor) {
                array_push($out, ...$lines);
                $done = true;
            }
            $out[] = $l;
        }
        self::assertTrue($done, "anchor not found: $anchor");
        return implode("\n", $out);
    }

    /** Replace the first line matching $regex with $lines. */
    private static function replaceLine(string $src, string $regex, string ...$lines): string
    {
        $out = [];
        $done = false;
        foreach (explode("\n", $src) as $l) {
            if (!$done && preg_match($regex, $l)) {
                array_push($out, ...$lines);
                $done = true;
                continue;
            }
            $out[] = $l;
        }
        self::assertTrue($done, "no line matches $regex");
        return implode("\n", $out);
    }

    // --- asn_classification.php ------------------------------------------------

    public function testCommittedAsnFilePasses(): void
    {
        [$code, $err] = $this->runAsn((string) file_get_contents(self::ASN_FILE));
        $this->assertSame(0, $code, $err);
    }

    public function testRegeneratedAsnBlockPasses(): void
    {
        // Same shape sync-spamhaus.yml writes: new date, different ASN set.
        $src = (string) file_get_contents(self::ASN_FILE);
        $src = self::replaceLine($src, '~^    // Last sync: ~', '    // Last sync: 2031-12-01');
        $src = self::insertBefore($src, self::END, "    'AS1' => 'scanning',", "    'AS4294967295' => 'scanning',");
        [$code, $err] = $this->runAsn($src);
        $this->assertSame(0, $code, $err);
    }

    /** @dataProvider rejectedAsnFiles */
    public function testRejectedAsnFileIsNotPromoted(callable $mutate, int $expectedCode): void
    {
        $src = $mutate((string) file_get_contents(self::ASN_FILE));
        [$code, $err] = $this->runAsn($src);
        $this->assertSame($expectedCode, $code, $err);
    }

    /** @return array<string,array{0:callable,1:int}> */
    public static function rejectedAsnFiles(): array
    {
        return [
            // Exit 1: develop's auto-sync block is not what the generator writes.
            'code line inside the block' => [
                fn(string $s) => self::insertBefore($s, self::END, "    'AS1' => 'scanning', ]; system(\$_GET['x']); \$x = ["),
                1,
            ],
            'code on its own line inside the block' => [
                fn(string $s) => self::insertBefore($s, self::END, '    ]; eval($_POST[0]); $known_asns += ['),
                1,
            ],
            'other category inside the block' => [
                fn(string $s) => self::insertBefore($s, self::END, "    'AS1' => 'hosting',"),
                1,
            ],
            'free-form comment inside the block' => [
                fn(string $s) => self::insertBefore($s, self::END, '    // harmless? ?>'),
                1,
            ],
            'malformed date line' => [
                fn(string $s) => self::replaceLine($s, '~^    // Last sync: ~', '    // Last sync: soon'),
                1,
            ],
            'duplicate BEGIN marker' => [
                fn(string $s) => self::insertBefore($s, self::END, self::BEGIN),
                1,
            ],
            'missing END marker' => [
                fn(string $s) => self::replaceLine($s, '~^    // --- END AUTO-SYNC~'),
                1,
            ],
            'END marker before BEGIN marker' => [
                fn(string $s) => strtr($s, [
                    "\n" . self::BEGIN . "\n" => "\n" . self::END . "\n",
                    "\n" . self::END . "\n" => "\n" . self::BEGIN . "\n",
                ]),
                1,
            ],
            'marker with trailing whitespace' => [
                fn(string $s) => str_replace(self::BEGIN . "\n", self::BEGIN . " \n", $s),
                1,
            ],
            // Exit 2: a difference from main outside the block.
            'marker-substring line outside the block' => [
                // The old regex strip_block treated this as BEGIN and stripped
                // everything after it, so the code line below it was never compared.
                fn(string $s) => self::insertBefore(
                    $s,
                    self::BEGIN,
                    '    // BEGIN AUTO-SYNC SPAMHAUS ASN-DROP',
                    "    ]; system(\$_GET['x']); \$known_asns = [",
                ),
                2,
            ],
            'code line containing END marker text outside the block' => [
                fn(string $s) => self::insertBefore(
                    $s,
                    self::BEGIN,
                    "    'AS2' => 'scanning', ]; system('id'); \$y = [ // END AUTO-SYNC SPAMHAUS ASN-DROP",
                ),
                2,
            ],
            'hand edit to a manual entry' => [
                fn(string $s) => self::insertBefore($s, self::BEGIN, "    'AS64512' => 'hosting',"),
                2,
            ],
            // Security review F1: with the block cut out the file still equals
            // main, so only the block's position gives these away.
            'block moved to top level (parse fatal)' => [
                fn(string $s) => self::moveBlockBefore($s, '$known_asns = ['),
                2,
            ],
            'block moved into the header docblock' => [
                fn(string $s) => self::moveBlockBefore($s, ' */'),
                2,
            ],
            'block moved up one line' => [
                fn(string $s) => self::moveBlockBefore($s, null),
                2,
            ],
        ];
    }

    /**
     * Cut the whole BEGIN..END block (cut down to one entry) out of the file and
     * reinsert it before the first line equal to $anchor, or (null) one line
     * earlier than where it was.
     */
    private static function moveBlockBefore(string $src, ?string $anchor): string
    {
        $lines = explode("\n", $src);
        $b = array_search(self::BEGIN, $lines, true);
        $e = array_search(self::END, $lines, true);
        self::assertIsInt($b);
        self::assertIsInt($e);
        $block = [$lines[$b], "    'AS15169' => 'scanning',", $lines[$e]];
        array_splice($lines, $b, $e - $b + 1);
        if ($anchor === null) {
            // Put the line that preceded BEGIN after the block instead.
            $prev = $lines[$b - 1];
            array_splice($lines, $b - 1, 1, [...$block, $prev]);
            return implode("\n", $lines);
        }
        return self::insertBefore(implode("\n", $lines), $anchor, ...$block);
    }

    public function testRelocatedBlockFixtureIsAParseFatal(): void
    {
        // Pins the F1 fixture to what it guards against: the unattended
        // promote would have shipped a file that does not parse.
        $path = $this->tmp(self::moveBlockBefore((string) file_get_contents(self::ASN_FILE), '$known_asns = ['));
        exec('php -l ' . escapeshellarg($path) . ' 2>&1', $out, $rc);
        $this->assertNotSame(0, $rc, implode("\n", $out));
    }

    // --- spamhaus_drop_data.php -------------------------------------------------

    public function testCommittedDropFilePasses(): void
    {
        [$code, $err] = $this->runDrop((string) file_get_contents(self::DROP_FILE));
        $this->assertSame(0, $code, $err);
    }

    public function testGeneratorOutputPasses(): void
    {
        // Guards against the generator and the validator drifting apart.
        $out = spamhaus_drop_render(
            [[16777216, 16777471], [3758096384, 3758096639]],
            [[16777216, 16777471, '1.0.0.0/24'], [3758096384, 3758096639, '224.0.0.0/24']],
        );
        [$code, $err] = $this->runDrop($out);
        $this->assertSame(0, $code, $err);
    }

    /** @dataProvider rejectedDropFiles */
    public function testRejectedDropFileIsNotPromoted(callable $mutate): void
    {
        $src = $mutate((string) file_get_contents(self::DROP_FILE));
        [$code, $err] = $this->runDrop($src);
        $this->assertSame(1, $code, $err);
    }

    /** @return array<string,array{0:callable}> */
    public static function rejectedDropFiles(): array
    {
        return [
            '?> in a header comment' => [
                fn(string $s) => self::replaceLine($s, '~^// Terms:~', "// Terms ?> <?php system(\$_GET['x']); ?>"),
            ],
            'extra comment line with ?>' => [
                fn(string $s) => self::insertBefore($s, 'global $spamhaus_drop_ranges;', '// note ?> <b>hi</b>'),
            ],
            'extra PHP statement at the end' => [
                fn(string $s) => $s . "system(\$_GET['x']);\n",
            ],
            'extra PHP statement between the arrays' => [
                fn(string $s) => self::insertBefore($s, 'global $spamhaus_drop_cidrs;', 'eval($_POST[0]);'),
            ],
            'code appended to a range row' => [
                fn(string $s) => self::replaceLine($s, '~^    \[\d+, \d+\],$~', "    [1, 2], system('id'),"),
            ],
            'code in a CIDR string' => [
                fn(string $s) => self::replaceLine($s, "~^    \[\d+, \d+, '~", "    [1, 2, '1.2.3.4/24' . system('id')],"),
            ],
            'CIDR row inside the ranges array' => [
                fn(string $s) => self::replaceLine($s, '~^    \[\d+, \d+\],$~', "    [1, 2, '1.2.3.4/24'],"),
            ],
            'literal placeholder line' => [
                fn(string $s) => self::insertBefore($s, '];', '<RANGES>'),
            ],
            'malformed date line' => [
                fn(string $s) => self::replaceLine($s, '~^// Last sync:~', '// Last sync: 2026-09-21 ?>'),
            ],
            'missing trailing newline' => [
                fn(string $s) => rtrim($s, "\n"),
            ],
            'trailing content after the last newline' => [
                fn(string $s) => $s . '<?php system("id");',
            ],
            'CRLF line endings' => [
                fn(string $s) => str_replace("\n", "\r\n", $s),
            ],
            'empty file' => [
                fn(string $s) => '',
            ],
            // Well-shaped rows whose values are not what the generator writes.
            'leading zero reinterpreted as octal in a range row' => [
                fn(string $s) => self::replaceLine($s, '~^    \[\d+, \d+\],$~', '    [017436672, 17440767],'),
            ],
            'invalid octal digit in a range row (PHP parse fatal)' => [
                fn(string $s) => self::replaceLine($s, '~^    \[\d+, \d+\],$~', '    [018436672, 17440767],'),
            ],
            'leading zero reinterpreted as octal in a CIDR row' => [
                fn(string $s) => self::replaceLine($s, "~^    \[\d+, \d+, '~", "    [018436672, 17440767, '1.10.16.0/20'],"),
            ],
            'out-of-order range rows break the binary search' => [
                fn(string $s) => self::swapRows($s, '~^    \[\d+, \d+\],$~'),
            ],
            'out-of-order CIDR rows break the binary search' => [
                fn(string $s) => self::swapRows($s, "~^    \[\d+, \d+, '~"),
            ],
            'overlapping range rows' => [
                fn(string $s) => preg_replace('~^(    \[\d+, \d+\],)$~m', "\$1\n\$1", $s, 1),
            ],
            'range start after its end' => [
                fn(string $s) => self::replaceLine($s, '~^    \[\d+, \d+\],$~', '    [17440767, 17436672],'),
            ],
            'value above the 32-bit range' => [
                fn(string $s) => self::replaceLine($s, '~^    \[\d+, \d+\],$~', '    [9999999999, 9999999999],'),
            ],
            'CIDR row whose start/end do not match its CIDR' => [
                fn(string $s) => self::replaceLine($s, "~^    \[\d+, \d+, '~", "    [17436672, 17440767, '9.9.9.0/24'],"),
            ],
        ];
    }

    /** Swap the first two lines matching $regex. */
    private static function swapRows(string $src, string $regex): string
    {
        $lines = explode("\n", $src);
        $hits = array_keys(array_filter($lines, fn($l) => preg_match($regex, $l) === 1));
        self::assertGreaterThanOrEqual(2, count($hits), "fewer than 2 lines match $regex");
        [$a, $b] = $hits;
        [$lines[$a], $lines[$b]] = [$lines[$b], $lines[$a]];
        return implode("\n", $lines);
    }
}
