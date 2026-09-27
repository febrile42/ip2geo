<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../api/lookup.php';
require_once __DIR__ . '/../includes/extract.php';

/**
 * The lookup rate limit is a per-minute cost budget, not a request count
 * (IPG-48). APCu is modelled with an in-memory store whose entries never
 * expire, which is what apcu_inc() with the default TTL of 0 really did:
 * the old limiter only reset when APCu restarted.
 */
class RateLimitBudgetTest extends TestCase
{
    private const T0 = 1_790_000_040; // start of a 60s window

    /** @var array<string,int> */
    private array $store = [];

    private function increment(): callable
    {
        return function (string $key, int $step, int $ttl): int {
            $this->store[$key] = ($this->store[$key] ?? 0) + $step;
            return $this->store[$key];
        };
    }

    private function charge(string $ip, int $cost, int $now = self::T0, string $bucket = \LOOKUP_RATE_BUCKET_API): array
    {
        return \default_lookup_rate_limiter($ip, $bucket, $cost, $this->increment(), $now);
    }

    public function testCostIsOnePlusOnePerFullThousandIps(): void
    {
        $this->assertSame(1, \lookup_rate_cost(0));
        $this->assertSame(1, \lookup_rate_cost(1));
        $this->assertSame(1, \lookup_rate_cost(999));
        $this->assertSame(2, \lookup_rate_cost(1000));
        $this->assertSame(10, \lookup_rate_cost(9999));
        $this->assertSame(11, \lookup_rate_cost(10000));
        $this->assertSame(11, \lookup_rate_cost(\EXTRACT_IPS_CAP), 'no-JS POSTs are charged as a full lookup');
    }

    public function testSixHundredSmallLookupsPerMinuteThenLimited(): void
    {
        for ($i = 0; $i < 600; $i++) {
            $this->assertFalse($this->charge('198.51.100.1', 1)['limited'], "lookup #" . ($i + 1));
        }
        $this->assertTrue($this->charge('198.51.100.1', 1)['limited']);
    }

    public function testFiftyFourMaxSizeLookupsPerMinuteThenLimited(): void
    {
        for ($i = 0; $i < 54; $i++) {
            $this->assertFalse($this->charge('198.51.100.1', 11)['limited'], "lookup #" . ($i + 1));
        }
        $this->assertTrue($this->charge('198.51.100.1', 11)['limited']);
    }

    // The IPG-48 root cause: the counter never expired, so "60/minute" was "60 ever".
    public function testNextWindowStartsWithAFreshBudgetEvenIfNothingExpires(): void
    {
        for ($i = 0; $i < 55; $i++) {
            $this->charge('198.51.100.1', 11);
        }
        $this->assertTrue($this->charge('198.51.100.1', 1, self::T0 + 59)['limited']);
        $this->assertFalse($this->charge('198.51.100.1', 1, self::T0 + 60)['limited']);
    }

    public function testRetryAfterIsTheTimeLeftInTheWindow(): void
    {
        $this->charge('198.51.100.1', 600, self::T0 + 15);
        $result = $this->charge('198.51.100.1', 1, self::T0 + 15);

        $this->assertTrue($result['limited']);
        $this->assertSame(45, $result['retry_after']);
    }

    public function testClientsAndBucketsDoNotShareABudget(): void
    {
        $this->charge('198.51.100.1', 600);
        $this->assertTrue($this->charge('198.51.100.1', 1)['limited']);

        $this->assertFalse($this->charge('198.51.100.2', 1)['limited']);
        $this->assertFalse($this->charge('198.51.100.1', 1, self::T0, \LOOKUP_RATE_BUCKET_NOJS)['limited']);
    }

    // IPG-145: rotating /64s inside one /56 doesn't mint new budgets.
    public function testIpv6Slash56SharesOneBudget(): void
    {
        $this->charge('2001:db8:1:200::1', 600);
        $this->assertTrue($this->charge('2001:db8:1:2ab::ffff', 1)['limited']);
        $this->assertTrue($this->charge('2001:db8:1:2ff:1::1', 1)['limited']);
        $this->assertFalse($this->charge('2001:db8:1:300::1', 1)['limited']);
    }

    // ── global ceiling (IPG-145) ────────────────────────────────────────────

    public function testGlobalCeilingLimitsManyClientsEachWithinTheirOwnBudget(): void
    {
        // Every client stays under its 600 units; together they hit the ceiling.
        $spent = 0;
        for ($i = 1; $spent + 11 <= \LOOKUP_RATE_GLOBAL_MAX_API; $i++) {
            $this->assertFalse($this->charge('198.51.100.' . $i, 11)['limited'], "client #$i");
            $spent += 11;
        }
        $result = $this->charge('203.0.113.1', 11, self::T0 + 20);

        $this->assertTrue($result['limited'], 'a fresh client is refused once the global budget is spent');
        $this->assertSame('global', $result['reason']);
        $this->assertSame(40, $result['retry_after']);
    }

    public function testGlobalCeilingResetsNextWindow(): void
    {
        $this->charge('198.51.100.1', 600);
        $this->charge('198.51.100.2', \LOOKUP_RATE_GLOBAL_MAX_API - 600);
        $this->assertTrue($this->charge('198.51.100.3', 1, self::T0 + 59)['limited']);
        $this->assertFalse($this->charge('198.51.100.3', 1, self::T0 + 60)['limited']);
    }

    public function testGlobalCeilingIsPerPath(): void
    {
        $this->charge('198.51.100.1', \LOOKUP_RATE_GLOBAL_MAX_NOJS, self::T0, \LOOKUP_RATE_BUCKET_NOJS);

        $nojs = $this->charge('198.51.100.2', 11, self::T0, \LOOKUP_RATE_BUCKET_NOJS);
        $this->assertTrue($nojs['limited']);
        $this->assertSame('global', $nojs['reason']);
        $this->assertFalse($this->charge('198.51.100.2', 11)['limited'], 'a no-JS flood leaves the API working');
    }

    public function testAClientOverItsOwnBudgetDoesNotDrainTheGlobalOne(): void
    {
        $this->charge('198.51.100.1', 600);
        for ($i = 0; $i < 1000; $i++) {
            $this->assertSame('client', $this->charge('198.51.100.1', 11)['reason']);
        }
        $this->assertFalse($this->charge('198.51.100.2', 11)['limited']);
    }

    // ── fails closed without APCu (IPG-145) ─────────────────────────────────

    public function testFailsClosedWithoutAStore(): void
    {
        $result = \lookup_rate_check('198.51.100.1', \LOOKUP_RATE_BUCKET_API, 1, null, self::T0 + 15);

        $this->assertTrue($result['limited']);
        $this->assertSame('unavailable', $result['reason']);
        $this->assertSame(45, $result['retry_after']);
    }

    public function testDefaultLimiterFailsClosedWhenApcuIsNotUsable(): void
    {
        if (\lookup_rate_apcu_increment() !== null) {
            $this->markTestSkipped('APCu is loaded and enabled for the CLI here; covered by testFailsClosedWithoutAStore.');
        }
        $result = \default_lookup_rate_limiter('198.51.100.1');

        $this->assertTrue($result['limited']);
        $this->assertSame('unavailable', $result['reason']);
    }

    public function testLetsTheRequestThroughWhenOneIncrementErrors(): void
    {
        $result = \default_lookup_rate_limiter('198.51.100.1', \LOOKUP_RATE_BUCKET_API, 1, static fn() => false, self::T0);
        $this->assertFalse($result['limited']);
    }

    // ── api/lookup.php charges by unique IP count ───────────────────────────

    /** Sends $ips to the API and returns the cost the limiter was charged. */
    private function apiCostFor(array $ips): int
    {
        $costs = [];
        handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            json_encode(['ips' => $ips]),
            static fn(array $ips): array => [],
            function (string $ip, int $cost) use (&$costs): array {
                $costs[] = $cost;
                return ['limited' => true, 'retry_after' => 1];
            }
        );

        $this->assertCount(1, $costs);
        return $costs[0];
    }

    public function testApiChargesByUniqueIpCount(): void
    {
        $this->assertSame(1, $this->apiCostFor(['1.2.3.4']));
        $this->assertSame(1, $this->apiCostFor(array_fill(0, 5000, '1.2.3.4')), 'duplicates are free');

        $ips = [];
        for ($i = 0; $i < 10000; $i++) {
            $ips[] = long2ip(0x01000000 + $i);
        }
        $this->assertSame(11, $this->apiCostFor($ips));
    }
}
