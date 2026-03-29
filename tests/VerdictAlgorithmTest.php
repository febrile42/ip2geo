<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';

/**
 * Tests for compute_verdict() and maybe_upgrade_verdict().
 *
 * All boundary conditions from the spec:
 *  HIGH:     ≥80% scanning  OR  ≥60% scanning AND ≥100 IPs absolute
 *  LOW:      <30% scanning  OR  <10 scanning IPs
 *  MODERATE: everything else
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
        // 80 of 120 → ~66.7%, 80 abs ≥ 100 → HIGH (both ≥60% and ≥100 abs conditions met)
        $this->assertSame('HIGH', compute_verdict(100, 150));
    }

    public function testSixtyPercentWithUnder100AbsoluteIsModerate(): void
    {
        // 60 of 100 → 60%, only 60 abs (< 100) → MODERATE (percentage threshold met but not absolute)
        $this->assertSame('MODERATE', compute_verdict(60, 100));
    }

    public function testExactly100AbsoluteAt60PctIsHigh(): void
    {
        // Exactly at the absolute boundary: 100 scanning, 60%+ → HIGH
        $this->assertSame('HIGH', compute_verdict(100, 166));  // 60.2%
    }

    public function testJustUnderSixtyPercentWithLargeVolumeIsModerate(): void
    {
        // 59 of 100 → 59%, 59 abs → MODERATE
        $this->assertSame('MODERATE', compute_verdict(59, 100));
    }

    public function testThirtyPercentBoundaryIsLow(): void
    {
        // 29 of 100 → 29% → LOW
        $this->assertSame('LOW', compute_verdict(29, 100));
    }

    public function testExactlyThirtyPercentIsModerate(): void
    {
        // 30 of 100 → 30% → MODERATE (not <30%)
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
