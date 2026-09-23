<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The public "Try a sample log" demo (R13) must never label a real person's
 * IP an attacker. Every address in assets/sample-fail2ban.txt has to fall
 * inside one of the published scanner / Spamhaus DROP / cloud-hosting CIDRs
 * committed at tests/fixtures/sample-sources.txt — no DB or network lookups,
 * just IP arithmetic against a static allowlist.
 *
 * The visitor's own "(you)" line (R16) is injected at runtime by JS and is
 * not part of this static file, so it is out of scope here.
 */
class SampleLogTest extends TestCase
{
    private const SAMPLE_LOG = __DIR__ . '/../assets/sample-fail2ban.txt';
    private const SOURCES = __DIR__ . '/fixtures/sample-sources.txt';

    /** @return array<int,string> */
    private function nonCommentLines(): array
    {
        $text = file_get_contents(self::SAMPLE_LOG);
        $this->assertNotFalse($text, 'assets/sample-fail2ban.txt must be readable');

        $lines = preg_split('/\r\n|\r|\n/', $text);
        $lines = array_filter($lines, function (string $line): bool {
            $trimmed = ltrim($line);
            return $trimmed !== '' && $trimmed[0] !== '#';
        });

        return array_values($lines);
    }

    /** @return array<int,string> CIDRs (v4 and v6), comments/blank lines stripped */
    private function sourceCidrs(): array
    {
        $text = file_get_contents(self::SOURCES);
        $this->assertNotFalse($text, 'tests/fixtures/sample-sources.txt must be readable');

        $lines = preg_split('/\r\n|\r|\n/', $text);
        $cidrs = [];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || $trimmed[0] === '#') {
                continue;
            }
            $cidrs[] = $trimmed;
        }

        return $cidrs;
    }

    /**
     * Pulls every IPv4/IPv6 literal out of a log line. IPv6 addresses always
     * contain "::" or at least one hex-letter group in this file (they come
     * from real cloud CIDRs), which keeps this from matching bare HH:MM:SS
     * timestamps that also contain colon-separated digits.
     *
     * @return array<int,string>
     */
    private function extractIps(string $line): array
    {
        $ips = [];

        if (preg_match_all(
            '/(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])(?![0-9.])/',
            $line,
            $m
        )) {
            foreach ($m[0] as $candidate) {
                if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                    $ips[] = $candidate;
                }
            }
        }

        // IPv6 candidates: token containing at least two colons, bounded by whitespace.
        if (preg_match_all('/[0-9A-Fa-f:]*::[0-9A-Fa-f:]*|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}/', $line, $m)) {
            foreach ($m[0] as $candidate) {
                $candidate = trim($candidate, ':');
                if ($candidate === '' || strpos($candidate, '::') === false) {
                    continue; // skip anything that isn't a real compressed v6 literal
                }
                if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                    $ips[] = $candidate;
                }
            }
        }

        return $ips;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return false;
        }
        [$net, $prefixStr] = explode('/', $cidr, 2);
        $prefix = (int) $prefixStr;

        $ipIsV6 = strpos($ip, ':') !== false;
        $netIsV6 = strpos($net, ':') !== false;
        if ($ipIsV6 !== $netIsV6) {
            return false;
        }

        $ipBin = @inet_pton($ip);
        $netBin = @inet_pton($net);
        if ($ipBin === false || $netBin === false) {
            return false;
        }

        $bytes = strlen($netBin);
        $fullBytes = intdiv($prefix, 8);
        $remBits = $prefix % 8;

        if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($netBin, 0, $fullBytes)) {
            return false;
        }
        if ($remBits > 0 && $fullBytes < $bytes) {
            $mask = 0xFF << (8 - $remBits) & 0xFF;
            $ipByte = ord($ipBin[$fullBytes]);
            $netByte = ord($netBin[$fullBytes]);
            if (($ipByte & $mask) !== ($netByte & $mask)) {
                return false;
            }
        }

        return true;
    }

    private function ipInAnyCidr(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if ($this->ipInCidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    public function testEveryIpFallsInsideAPublishedSourceCidr(): void
    {
        $cidrs = $this->sourceCidrs();
        $this->assertNotEmpty($cidrs, 'sample-sources.txt must list at least one CIDR');

        $lines = $this->nonCommentLines();
        $this->assertNotEmpty($lines, 'sample-fail2ban.txt must have log lines');

        $checked = 0;
        foreach ($lines as $line) {
            foreach ($this->extractIps($line) as $ip) {
                $checked++;
                $this->assertTrue(
                    $this->ipInAnyCidr($ip, $cidrs),
                    "IP $ip (from line: $line) is not inside any CIDR in tests/fixtures/sample-sources.txt"
                );
            }
        }

        $this->assertGreaterThan(0, $checked, 'expected to find at least one IP across the sample log');
    }

    public function testLineCountIsWithinRange(): void
    {
        $count = count($this->nonCommentLines());
        $this->assertGreaterThanOrEqual(150, $count, 'expected at least 150 non-comment log lines');
        $this->assertLessThanOrEqual(250, $count, 'expected at most 250 non-comment log lines');
    }

    public function testUniqueIpCountIsWithinRange(): void
    {
        $unique = [];
        foreach ($this->nonCommentLines() as $line) {
            foreach ($this->extractIps($line) as $ip) {
                $unique[$ip] = true;
            }
        }
        $count = count($unique);
        $this->assertGreaterThanOrEqual(50, $count, 'expected at least 50 unique IPs');
        $this->assertLessThanOrEqual(100, $count, 'expected at most 100 unique IPs');
    }

    public function testHasIpv6Addresses(): void
    {
        $v6 = 0;
        foreach ($this->nonCommentLines() as $line) {
            foreach ($this->extractIps($line) as $ip) {
                if (strpos($ip, ':') !== false) {
                    $v6++;
                }
            }
        }
        $this->assertGreaterThan(0, $v6, 'expected at least one IPv6 line in the sample log');
    }

    public function testHeaderDeclaresSyntheticSourcesAndDate(): void
    {
        $text = file_get_contents(self::SAMPLE_LOG);
        $this->assertNotFalse($text);

        $headerLines = [];
        foreach (preg_split('/\r\n|\r|\n/', $text) as $line) {
            if (isset($line[0]) && $line[0] === '#') {
                $headerLines[] = $line;
            } else {
                break;
            }
        }
        $header = implode("\n", $headerLines);

        $this->assertMatchesRegularExpression('/\b(2026-09-2\d|Generated:)\b/', $header, 'header should state a generation date');
        $this->assertStringContainsStringIgnoringCase('synthetic', $header);
        $this->assertStringContainsString('spamhaus.org', $header);
        $this->assertStringContainsString('censys.com', $header);
        $this->assertStringContainsString('amazonaws.com', $header);
    }
}
