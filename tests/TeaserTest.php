<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';

/**
 * build_teaser() — the inline threat-score teaser reveal logic.
 *
 * Pure function, no DB/network. The load-bearing invariant under test:
 * locked_count derives from the flagged count passed in, NOT from the enriched
 * scores (only the top 1-2 are enriched live; the rest are null on a cold
 * cache). A naive "count scores > 80 across the list" would read ~0 exactly
 * when a user first investigates a real attack — these tests lock that out.
 */
class TeaserTest extends TestCase
{
    public function testRevealsScoreAboveThreshold(): void
    {
        $t = build_teaser([['ip' => '45.155.205.1', 'abuse_score' => 96]], 42);
        $this->assertSame([['ip' => '45.155.205.1', 'score' => 96]], $t['samples']);
        $this->assertSame(42, $t['locked_count']);
    }

    public function testHidesScoreExactlyAtThreshold(): void
    {
        // > 80 strictly, matching maybe_upgrade_verdict's verified-attacker bar.
        $t = build_teaser([['ip' => '1.2.3.4', 'abuse_score' => 80]], 10);
        $this->assertSame([], $t['samples']);
        $this->assertSame(10, $t['locked_count']);
    }

    public function testHidesScoreBelowThreshold(): void
    {
        $t = build_teaser([['ip' => '1.2.3.4', 'abuse_score' => 50]], 10);
        $this->assertSame([], $t['samples']);
    }

    public function testHidesNullScore(): void
    {
        $t = build_teaser([['ip' => '1.2.3.4', 'abuse_score' => null]], 10);
        $this->assertSame([], $t['samples']);
    }

    public function testHidesMissingScoreKey(): void
    {
        $t = build_teaser([['ip' => '1.2.3.4']], 10);
        $this->assertSame([], $t['samples']);
    }

    /** The load-bearing one: cold cache (all null) still shows a real locked count. */
    public function testLockedCountComesFromFlaggedNotEnrichedScores(): void
    {
        $coldCacheTop25 = array_fill(0, 25, ['ip' => '1.1.1.1', 'abuse_score' => null]);
        $t = build_teaser($coldCacheTop25, 42);
        $this->assertSame([], $t['samples'], 'no scores to reveal on a cold cache');
        $this->assertSame(42, $t['locked_count'], 'locked_count must reflect flagged IPs, not enriched scores');
    }

    public function testCapsAtTwoSamples(): void
    {
        $t = build_teaser([
            ['ip' => 'a', 'abuse_score' => 99],
            ['ip' => 'b', 'abuse_score' => 95],
            ['ip' => 'c', 'abuse_score' => 90],
        ], 5);
        $this->assertCount(2, $t['samples']);
        $this->assertSame('a', $t['samples'][0]['ip']);
        $this->assertSame('b', $t['samples'][1]['ip']);
    }

    public function testPreservesRankedOrderAndSkipsLowScores(): void
    {
        $t = build_teaser([
            ['ip' => 'top', 'abuse_score' => 95],
            ['ip' => 'clean', 'abuse_score' => 30],
            ['ip' => 'second', 'abuse_score' => 82],
            ['ip' => 'third', 'abuse_score' => 88],
        ], 7);
        $this->assertSame(
            [['ip' => 'top', 'score' => 95], ['ip' => 'second', 'score' => 82]],
            $t['samples']
        );
    }

    public function testEmptyEnrichedAndZeroFlagged(): void
    {
        $t = build_teaser([], 0);
        $this->assertSame([], $t['samples']);
        $this->assertSame(0, $t['locked_count']);
    }

    public function testNegativeFlaggedClampedToZero(): void
    {
        $t = build_teaser([], -3);
        $this->assertSame(0, $t['locked_count']);
    }

    public function testCustomThreshold(): void
    {
        $t = build_teaser([['ip' => 'x', 'abuse_score' => 70]], 1, 60);
        $this->assertSame([['ip' => 'x', 'score' => 70]], $t['samples']);
    }
}
