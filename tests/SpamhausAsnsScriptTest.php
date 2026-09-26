<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * scripts/spamhaus-asns.sh: the gate between the untrusted Spamhaus ASN-DROP
 * feed and the PHP source that sync-spamhaus.yml writes and auto-promotes to
 * production. Every value it emits becomes a PHP string literal, so anything
 * other than a plain integer ASN must fail the run with nothing on stdout.
 */
class SpamhausAsnsScriptTest extends TestCase
{
    private const SCRIPT = __DIR__ . '/../scripts/spamhaus-asns.sh';

    private const METADATA = '{"type":"metadata","timestamp":1790381642,"size":38254,"records":2}';

    protected function setUp(): void
    {
        if (trim((string) shell_exec('command -v jq')) === '') {
            $this->markTestSkipped('jq is not installed');
        }
    }

    /** @return array{0:int,1:string,2:string} exit code, stdout, stderr */
    private function runScript(string $feed): array
    {
        $proc = proc_open(
            ['bash', self::SCRIPT],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        fwrite($pipes[0], $feed);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($proc), $stdout, $stderr];
    }

    public function testValidFeedEmitsSortedUniqueAsnsAndSkipsMetadata(): void
    {
        $feed = implode("\n", [
            '{"asn":2601,"rir":"ripencc","domain":"pitline.net","cc":"UA","asname":"RADIOLINK-AS"}',
            '{"asn":245,"rir":"arin","domain":"planningresearchcorp.com","cc":"US","asname":"PRC-AS"}',
            '{"asn":245,"rir":"arin","domain":"planningresearchcorp.com","cc":"US","asname":"PRC-AS"}',
            '{"asn":4294967295}',
            self::METADATA,
        ]) . "\n";

        [$code, $stdout] = $this->runScript($feed);

        $this->assertSame(0, $code);
        $this->assertSame("AS245\nAS2601\nAS4294967295\n", $stdout);
    }

    /** @dataProvider rejectedFeeds */
    public function testUnexpectedValueFailsClosedWithNothingEmitted(string $badLine): void
    {
        // A valid record around the bad one proves the whole run is rejected,
        // not just the offending record.
        $feed = '{"asn":245}' . "\n" . $badLine . "\n" . self::METADATA . "\n";

        [$code, $stdout] = $this->runScript($feed);

        $this->assertNotSame(0, $code, 'script must exit non-zero');
        $this->assertSame('', $stdout, 'script must emit nothing');
    }

    /** @return array<string,array{0:string}> */
    public static function rejectedFeeds(): array
    {
        return [
            'PHP injection string'   => ['{"asn":"1\'.system($_GET[x]).\'"}'],
            'numeric string'         => ['{"asn":"123"}'],
            'zero'                   => ['{"asn":0}'],
            'negative'               => ['{"asn":-3}'],
            'above 32 bits'          => ['{"asn":4294967296}'],
            'fractional'             => ['{"asn":1.5}'],
            'exponent literal'       => ['{"asn":1e5}'],
            'boolean'                => ['{"asn":true}'],
            'array'                  => ['{"asn":[245]}'],
            'object'                 => ['{"asn":{"n":245}}'],
            'non-JSON line'          => ['<html>502 Bad Gateway</html>'],
            'non-object record'      => ['"AS245"'],
        ];
    }

    public function testFeedWithNoAsnsFailsClosed(): void
    {
        [$code, $stdout] = $this->runScript(self::METADATA . "\n");
        $this->assertNotSame(0, $code);
        $this->assertSame('', $stdout);

        [$code, $stdout] = $this->runScript('');
        $this->assertNotSame(0, $code);
        $this->assertSame('', $stdout);
    }
}
