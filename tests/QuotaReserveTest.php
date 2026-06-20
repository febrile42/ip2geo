<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Atomic quota reserve-then-reconcile logic from enrich_abuseipdb()
 * (report_functions.php), tested against an in-memory SQLite DB.
 *
 * We mirror the exact SQL the function runs so drift is detectable:
 *
 *   ensure row : INSERT OR IGNORE INTO abuseipdb_daily_usage (mysql: INSERT ... ON DUPLICATE KEY UPDATE calls_made = calls_made)
 *   reserve    : UPDATE ... SET calls_made = calls_made + N WHERE usage_date = ? AND calls_made + N <= 1000
 *                -> affected_rows === 1 means reserved; 0 means over the cap (degrade)
 *   reconcile  : UPDATE ... SET calls_made = calls_made - (N - actual) WHERE usage_date = ?
 *
 * This is the fix for the prior TOCTOU: the check and the reserve are one
 * atomic statement, so two concurrent lookups can never both pass the 1000/day
 * cap, and no row lock is held across the network calls.
 */
class QuotaReserveTest extends TestCase
{
    private \PDO $pdo;
    private const CAP = 1000;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec("
            CREATE TABLE abuseipdb_daily_usage (
                usage_date DATE     PRIMARY KEY,
                calls_made SMALLINT NOT NULL DEFAULT 0
            )
        ");
    }

    private function insertUsage(string $date, int $calls): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT OR REPLACE INTO abuseipdb_daily_usage (usage_date, calls_made) VALUES (?, ?)'
        );
        $stmt->execute([$date, $calls]);
    }

    private function callsMade(string $date): int
    {
        $stmt = $this->pdo->prepare('SELECT calls_made FROM abuseipdb_daily_usage WHERE usage_date = ?');
        $stmt->execute([$date]);
        return (int)($stmt->fetchColumn() ?: 0);
    }

    /** Mirror the ensure-row + atomic reserve. Returns true if reserved. */
    private function reserve(string $date, int $batch): bool
    {
        $this->pdo->prepare('INSERT OR IGNORE INTO abuseipdb_daily_usage (usage_date, calls_made) VALUES (?, 0)')
            ->execute([$date]);
        $stmt = $this->pdo->prepare(
            'UPDATE abuseipdb_daily_usage
                SET calls_made = calls_made + ?
              WHERE usage_date = ? AND calls_made + ? <= ' . self::CAP
        );
        $stmt->execute([$batch, $date, $batch]);
        return $stmt->rowCount() === 1;
    }

    /** Mirror the reconcile of unused reservations. */
    private function reconcile(string $date, int $batch, int $actual): void
    {
        $unused = $batch - $actual;
        if ($unused > 0) {
            $stmt = $this->pdo->prepare(
                'UPDATE abuseipdb_daily_usage SET calls_made = calls_made - ? WHERE usage_date = ?'
            );
            $stmt->execute([$unused, $date]);
        }
    }

    public function testReserveSucceedsUnderBudget(): void
    {
        $d = '2026-06-19';
        $this->insertUsage($d, 50);
        $this->assertTrue($this->reserve($d, 10));
        $this->assertSame(60, $this->callsMade($d));
    }

    public function testReserveRejectedOverBudget(): void
    {
        $d = '2026-06-19';
        $this->insertUsage($d, 995);
        $this->assertFalse($this->reserve($d, 10)); // 995 + 10 = 1005 > 1000
        $this->assertSame(995, $this->callsMade($d), 'rejected reserve must not change the counter');
    }

    public function testReserveAllowedExactlyAtCap(): void
    {
        $d = '2026-06-19';
        $this->insertUsage($d, 990);
        $this->assertTrue($this->reserve($d, 10)); // 990 + 10 = 1000 <= 1000
        $this->assertSame(1000, $this->callsMade($d));
    }

    public function testReserveCreatesRowWhenMissing(): void
    {
        $d = '2026-06-19';
        $this->assertTrue($this->reserve($d, 5)); // no prior row
        $this->assertSame(5, $this->callsMade($d));
    }

    public function testReconcileReturnsUnusedReservations(): void
    {
        $d = '2026-06-19';
        $this->insertUsage($d, 50);
        $this->assertTrue($this->reserve($d, 10)); // -> 60
        $this->reconcile($d, 10, 7);               // 3 unused returned
        $this->assertSame(57, $this->callsMade($d), 'net change must equal actual calls made');
    }

    public function testReconcileNoOpWhenAllUsed(): void
    {
        $d = '2026-06-19';
        $this->insertUsage($d, 50);
        $this->reserve($d, 10);
        $this->reconcile($d, 10, 10); // nothing unused
        $this->assertSame(60, $this->callsMade($d));
    }

    public function testTwoConcurrentReservesCannotBothExceedCap(): void
    {
        // The TOCTOU fix: with calls_made at 997, two batches of 3 cannot both
        // land — the first reserves to 1000, the second is rejected.
        $d = '2026-06-19';
        $this->insertUsage($d, 997);
        $this->assertTrue($this->reserve($d, 3));  // -> 1000
        $this->assertFalse($this->reserve($d, 3)); // 1000 + 3 > 1000, rejected
        $this->assertSame(1000, $this->callsMade($d));
    }

    public function testTeaserSizedBatchReserves(): void
    {
        // The inline teaser only ever reserves 1-2 (top 1-2 IPs).
        $d = '2026-06-19';
        $this->insertUsage($d, 0);
        $this->assertTrue($this->reserve($d, 2));
        $this->assertSame(2, $this->callsMade($d));
    }
}
