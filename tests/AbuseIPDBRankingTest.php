<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';

/**
 * Tests for rank_ips().
 *
 * Ranking rule: score = freq × weight
 *   weight = 2  for scanning or vpn
 *   weight = 1  for cloud, residential, unknown
 *
 * Also covers maybe_upgrade_verdict() integration with AbuseIPDB scores.
 */
class AbuseIPDBRankingTest extends TestCase
{
    private function makeEntry(string $ip, string $cat, int $freq = 1, ?int $abuse = null): array
    {
        $e = ['ip' => $ip, 'classification' => $cat, 'freq' => $freq];
        if ($abuse !== null) $e['abuse_score'] = $abuse;
        return $e;
    }

    // ── rank_ips ───────────────────────────────────────────────────────────────

    public function testScanningBeatsCloudAtEqualFreq(): void
    {
        $data = [
            $this->makeEntry('10.0.0.2', 'cloud',    1),
            $this->makeEntry('10.0.0.1', 'scanning', 1),
        ];
        $ranked = rank_ips($data);
        $this->assertSame('10.0.0.1', $ranked[0]['ip']);
    }

    public function testVpnBeatsResidentialAtEqualFreq(): void
    {
        $data = [
            $this->makeEntry('10.0.0.2', 'residential', 1),
            $this->makeEntry('10.0.0.1', 'vpn',         1),
        ];
        $ranked = rank_ips($data);
        $this->assertSame('10.0.0.1', $ranked[0]['ip']);
    }

    public function testHighFreqCloudBeatsLowFreqScanning(): void
    {
        // cloud freq=10 → score 10; scanning freq=4 → score 8
        $data = [
            $this->makeEntry('10.0.0.1', 'scanning', 4),
            $this->makeEntry('10.0.0.2', 'cloud',    10),
        ];
        $ranked = rank_ips($data);
        $this->assertSame('10.0.0.2', $ranked[0]['ip']);
    }

    public function testScanningFreq5BeatsCloudFreq9(): void
    {
        // scanning freq=5 → score 10; cloud freq=9 → score 9
        $data = [
            $this->makeEntry('10.0.0.2', 'cloud',    9),
            $this->makeEntry('10.0.0.1', 'scanning', 5),
        ];
        $ranked = rank_ips($data);
        $this->assertSame('10.0.0.1', $ranked[0]['ip']);
    }

    public function testLimitRespected(): void
    {
        $data = [];
        for ($i = 0; $i < 30; $i++) {
            $data[] = $this->makeEntry('10.0.0.' . $i, 'cloud', $i + 1);
        }
        $ranked = rank_ips($data, 25);
        $this->assertCount(25, $ranked);
    }

    public function testDefaultLimitIs25(): void
    {
        $data = [];
        for ($i = 0; $i < 30; $i++) {
            $data[] = $this->makeEntry('10.0.0.' . $i, 'unknown', 1);
        }
        $this->assertCount(25, rank_ips($data));
    }

    public function testEmptyInputReturnsEmpty(): void
    {
        $this->assertSame([], rank_ips([]));
    }

    public function testMissingFreqDefaultsToOne(): void
    {
        $data = [
            ['ip' => '1.1.1.1', 'classification' => 'scanning'],  // no 'freq' key
        ];
        $ranked = rank_ips($data);
        $this->assertCount(1, $ranked);
        $this->assertSame('1.1.1.1', $ranked[0]['ip']);
    }

    public function testUnknownCategoryHasWeightOne(): void
    {
        // unknown freq=1 vs scanning freq=1; scanning should win
        $data = [
            $this->makeEntry('10.0.0.2', 'unknown',  1),
            $this->makeEntry('10.0.0.1', 'scanning', 1),
        ];
        $ranked = rank_ips($data);
        $this->assertSame('10.0.0.1', $ranked[0]['ip']);
    }

    public function testOrderIsStableForEqualScores(): void
    {
        // Two scanning IPs with same freq — result should contain both, order doesn't matter but count must be 2
        $data = [
            $this->makeEntry('10.0.0.1', 'scanning', 3),
            $this->makeEntry('10.0.0.2', 'scanning', 3),
        ];
        $ranked = rank_ips($data);
        $this->assertCount(2, $ranked);
    }

    // ── AbuseIPDB upgrade integration ─────────────────────────────────────────

    public function testUpgradeAppliesToTop5ByRankNotByInput(): void
    {
        // Build 6 entries. The 6th in rank position will have abuse_score=99.
        // After ranking, position 5 (0-indexed) has score 99 — should NOT upgrade.
        $data = [];
        // Five scanning IPs with high freq come first in rank
        for ($i = 1; $i <= 5; $i++) {
            $data[] = $this->makeEntry('10.0.0.' . $i, 'scanning', 10, 20);
        }
        // One residential with low freq and high abuse (will rank 6th)
        $data[] = $this->makeEntry('10.0.1.1', 'residential', 1, 99);

        $ranked = rank_ips($data);
        $verdict = maybe_upgrade_verdict('LOW', $ranked);

        // Top-5 abuse scores are all 20; 6th has 99 but is out of range
        $this->assertSame('LOW', $verdict);
    }

    public function testUpgradeTriggeredByPosition1(): void
    {
        $top25 = [$this->makeEntry('10.0.0.1', 'scanning', 10, 95)];
        $this->assertSame('HIGH', maybe_upgrade_verdict('MODERATE', $top25));
    }
}
