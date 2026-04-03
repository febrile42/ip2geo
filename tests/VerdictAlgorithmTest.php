<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';

/**
 * Tests for compute_verdict() and maybe_upgrade_verdict().
 *
 * All boundary conditions from the spec:
 *  HIGH:     ≥250 scanning abs  OR  (≥60% AND ≥20 abs)  OR  ≥80%
 *  LOW:      <10 scanning abs  OR  (<5% AND <25 abs)  — unless cloud floor applies
 *  MODERATE: everything else; LOW→MODERATE when cloud ≥50 abs or ≥15%
 *
 * AbuseIPDB upgrade:
 *  Any top-5 IP with confidence >80 bumps verdict one level.
 */
class VerdictAlgorithmTest extends TestCase
{
    // ── compute_verdict ────────────────────────────────────────────────────────

    public function testZeroTotalIsLow(): void
    {
        $this->assertSame('LOW', compute_verdict(0, 0));
    }

    public function testEightyPercentIsHigh(): void
    {
        // 8 of 10 → 80% → HIGH (boundary)
        $this->assertSame('HIGH', compute_verdict(8, 10));
    }

    public function testAboveEightyPercentIsHigh(): void
    {
        $this->assertSame('HIGH', compute_verdict(9, 10));
    }

    public function testSixtyPercentWithOver100AbsoluteIsHigh(): void
    {
        // 100 of 150 → ~66.7%, 100 abs ≥ 20 → HIGH
        $this->assertSame('HIGH', compute_verdict(100, 150));
    }

    public function testSixtyPercentWithOver20AbsoluteIsHigh(): void
    {
        // 60 of 100 → 60%, 60 abs ≥ 20 → HIGH (absolute threshold is 20, not 100)
        $this->assertSame('HIGH', compute_verdict(60, 100));
    }

    public function testSixtyPercentWithUnder20AbsoluteIsModerate(): void
    {
        // 12 of 20 → 60%, but only 12 abs (< 20) → MODERATE
        $this->assertSame('MODERATE', compute_verdict(12, 20));
    }

    public function testExactly20AbsoluteAt60PctIsHigh(): void
    {
        // Exactly at the absolute boundary: 20 scanning at 60%+ → HIGH
        $this->assertSame('HIGH', compute_verdict(20, 33));  // 60.6%
    }

    public function testAbsolute250IsHighRegardlessOfPct(): void
    {
        // 250 scanners out of 10000 (2.5%) → HIGH via absolute count trigger
        $this->assertSame('HIGH', compute_verdict(250, 10000));
    }

    public function testJustUnderSixtyPercentWithLargeVolumeIsModerate(): void
    {
        // 59 of 100 → 59%, 59 abs → MODERATE
        $this->assertSame('MODERATE', compute_verdict(59, 100));
    }

    public function testTwentyNinePercentAtHighVolumeIsModerate(): void
    {
        // 29 of 100 → 29%, 29 abs — not < 10, not < 5% → MODERATE (no 30% single-axis LOW)
        $this->assertSame('MODERATE', compute_verdict(29, 100));
    }

    public function testThirtyPercentIsModerate(): void
    {
        // 30 of 100 → 30% → MODERATE
        $this->assertSame('MODERATE', compute_verdict(30, 100));
    }

    public function testNineAbsoluteIsLow(): void
    {
        // 9 scanning IPs regardless of percentage → LOW
        $this->assertSame('LOW', compute_verdict(9, 20));
    }

    public function testTenAbsoluteAtThirtyPercentIsModerate(): void
    {
        // 10 scanning of 33 total → ~30% → MODERATE
        $this->assertSame('MODERATE', compute_verdict(10, 33));
    }

    public function testModerateRange(): void
    {
        // 40 of 100 → 40%, 40 abs → MODERATE
        $this->assertSame('MODERATE', compute_verdict(40, 100));
    }

    public function testAllScanning(): void
    {
        $this->assertSame('HIGH', compute_verdict(500, 500));
    }

    public function testAllResidential(): void
    {
        $this->assertSame('LOW', compute_verdict(0, 200));
    }

    public function testCloudFloorUpgradesLowToModerate(): void
    {
        // 5 scanners (LOW base) + 50 cloud IPs → MODERATE via cloud floor
        $this->assertSame('MODERATE', compute_verdict(5, 100, 50));
    }

    public function testCloudFloorAtFifteenPercentUpgradesLowToModerate(): void
    {
        // 5 scanners (LOW base) + 15% cloud → MODERATE via cloud floor
        $this->assertSame('MODERATE', compute_verdict(5, 200, 30));  // 30/200 = 15%
    }

    public function testLowCloudDoesNotAffectLowVerdict(): void
    {
        // 5 scanners (LOW base) + only 10 cloud (10%) → stays LOW
        $this->assertSame('LOW', compute_verdict(5, 100, 10));
    }

    // ── maybe_upgrade_verdict ──────────────────────────────────────────────────

    public function testNoUpgradeWhenAbuseScoreLow(): void
    {
        $top25 = [
            ['ip' => '1.2.3.4', 'abuse_score' => 50],
            ['ip' => '1.2.3.5', 'abuse_score' => 70],
        ];
        $this->assertSame('MODERATE', maybe_upgrade_verdict('MODERATE', $top25));
    }

    public function testModerateUpgradesToHighWhenTop5ScoreOver80(): void
    {
        $top25 = [
            ['ip' => '1.2.3.4', 'abuse_score' => 90],
        ];
        $this->assertSame('HIGH', maybe_upgrade_verdict('MODERATE', $top25));
    }

    public function testLowUpgradesToModerateWhenTop5ScoreOver80(): void
    {
        $top25 = [
            ['ip' => '1.2.3.4', 'abuse_score' => 81],
        ];
        $this->assertSame('MODERATE', maybe_upgrade_verdict('LOW', $top25));
    }

    public function testHighRemainsHighAfterUpgrade(): void
    {
        $top25 = [
            ['ip' => '1.2.3.4', 'abuse_score' => 100],
        ];
        $this->assertSame('HIGH', maybe_upgrade_verdict('HIGH', $top25));
    }

    public function testUpgradeOnlyChecksTop5NotPosition6(): void
    {
        // Positions 0-4 have low scores; position 5 has high score
        $top25 = array_merge(
            array_fill(0, 5, ['ip' => '1.1.1.1', 'abuse_score' => 20]),
            [['ip' => '2.2.2.2', 'abuse_score' => 99]]
        );
        // Position 5 (index 5) should NOT trigger upgrade
        $this->assertSame('MODERATE', maybe_upgrade_verdict('MODERATE', $top25));
    }

    public function testUpgradeWithMissingAbuseScore(): void
    {
        // Entries without abuse_score key should default to 0
        $top25 = [
            ['ip' => '1.2.3.4'],
            ['ip' => '1.2.3.5'],
        ];
        $this->assertSame('LOW', maybe_upgrade_verdict('LOW', $top25));
    }

    public function testNoUpgradeWhenTop25Empty(): void
    {
        $this->assertSame('MODERATE', maybe_upgrade_verdict('MODERATE', []));
    }

    public function testExactly80ScoreDoesNotUpgrade(): void
    {
        // Upgrade condition is >80, so exactly 80 should not upgrade
        $top25 = [['ip' => '1.2.3.4', 'abuse_score' => 80]];
        $this->assertSame('LOW', maybe_upgrade_verdict('LOW', $top25));
    }
}
