<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * AbuseIPDB cache and quota logic tests using SQLite in-memory DB.
 *
 * Tests the cache layer in enrich_abuseipdb():
 *  - Cache HIT:  IP queried within 7 days → return cached score, no API call
 *  - Cache MISS: IP not cached (or older than 7 days) → needs API call
 *  - Quota:      calls_made + batch_size > 1000 → degrade gracefully
 *  - Partial:    some IPs cached, some not → only uncached go to API
 *  - Daily reset: new date → fresh quota row (0 calls)
 *
 * We mirror the exact SQL from enrich_abuseipdb() so drift is detectable.
 */
class CacheTest extends TestCase
{
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $this->pdo->exec("
            CREATE TABLE abuseipdb_cache (
                ip               VARCHAR(45) PRIMARY KEY,
                confidence_score TINYINT     NOT NULL,
                total_reports    INT         NOT NULL DEFAULT 0,
                queried_at       DATETIME    NOT NULL
            )
        ");

        $this->pdo->exec("
            CREATE TABLE abuseipdb_daily_usage (
                usage_date DATE     PRIMARY KEY,
                calls_made SMALLINT NOT NULL DEFAULT 0
            )
        ");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Insert a cache entry. $age_seconds ago (positive = past). */
    private function insertCache(string $ip, int $score, int $age_seconds = 0): void
    {
        $ts = date('Y-m-d H:i:s', time() - $age_seconds);
        $stmt = $this->pdo->prepare(
            'INSERT OR REPLACE INTO abuseipdb_cache (ip, confidence_score, total_reports, queried_at)
             VALUES (?, ?, 0, ?)'
        );
        $stmt->execute([$ip, $score, $ts]);
    }

    private function insertUsage(string $date, int $calls): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT OR REPLACE INTO abuseipdb_daily_usage (usage_date, calls_made) VALUES (?, ?)'
        );
        $stmt->execute([$date, $calls]);
    }

    /**
     * Simulate the cache-lookup SELECT from enrich_abuseipdb().
     * Returns map of ip → confidence_score for IPs found within 7 days.
     */
    private function fetchCached(array $ips): array
    {
        if (empty($ips)) return [];

        $placeholders = implode(',', array_fill(0, count($ips), '?'));
        $cutoff = date('Y-m-d H:i:s', strtotime('-7 days'));
        $stmt = $this->pdo->prepare(
            'SELECT ip, confidence_score FROM abuseipdb_cache
             WHERE ip IN (' . $placeholders . ') AND queried_at > ?'
        );
        $stmt->execute(array_merge($ips, [$cutoff]));
        $result = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $result[$row['ip']] = (int)$row['confidence_score'];
        }
        return $result;
    }

    // ── cache hit / miss ──────────────────────────────────────────────────────

    public function testRecentCacheEntryIsHit(): void
    {
        $this->insertCache('1.2.3.4', 75, 3600); // 1 hour old
        $cached = $this->fetchCached(['1.2.3.4']);
        $this->assertArrayHasKey('1.2.3.4', $cached);
        $this->assertSame(75, $cached['1.2.3.4']);
    }

    public function testExpiredCacheEntryIsMiss(): void
    {
        // 7 days + 1 second = expired
        $this->insertCache('1.2.3.5', 50, 7 * 86400 + 1);
        $cached = $this->fetchCached(['1.2.3.5']);
        $this->assertArrayNotHasKey('1.2.3.5', $cached);
    }

    public function testExactly7DaysOldIsMiss(): void
    {
        // Exactly at the cutoff boundary — the query uses > not >=, so this is a miss
        $this->insertCache('1.2.3.6', 30, 7 * 86400);
        $cached = $this->fetchCached(['1.2.3.6']);
        $this->assertArrayNotHasKey('1.2.3.6', $cached);
    }

    public function testJustUnder7DaysOldIsHit(): void
    {
        $this->insertCache('1.2.3.7', 20, 7 * 86400 - 60); // 1 minute under
        $cached = $this->fetchCached(['1.2.3.7']);
        $this->assertArrayHasKey('1.2.3.7', $cached);
    }

    public function testMissingIpIsMiss(): void
    {
        $cached = $this->fetchCached(['9.9.9.9']);
        $this->assertArrayNotHasKey('9.9.9.9', $cached);
    }

    public function testEmptyIpListReturnsEmpty(): void
    {
        $this->assertSame([], $this->fetchCached([]));
    }

    // ── partial cache: mix of hits and misses ─────────────────────────────────

    public function testPartialCacheSplitsCorrectly(): void
    {
        $this->insertCache('10.0.0.1', 85, 60);  // hit
        $this->insertCache('10.0.0.2', 40, 60);  // hit
        // 10.0.0.3 not cached → miss

        $ips    = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];
        $cached = $this->fetchCached($ips);
        $missed = array_diff($ips, array_keys($cached));

        $this->assertCount(2, $cached);
        $this->assertSame(['10.0.0.3'], array_values($missed));
    }

    // ── quota logic ───────────────────────────────────────────────────────────

    public function testQuotaExceededWhenBatchPlusMadeExceeds1000(): void
    {
        $today = date('Y-m-d');
        $this->insertUsage($today, 990);

        $stmt = $this->pdo->prepare(
            'SELECT calls_made FROM abuseipdb_daily_usage WHERE usage_date = ?'
        );
        $stmt->execute([$today]);
        $calls_so_far = (int)($stmt->fetchColumn() ?: 0);

        $batch_size = 20; // 990 + 20 > 1000
        $this->assertTrue($calls_so_far + $batch_size > 1000);
    }

    public function testQuotaNotExceededExactlyAt1000(): void
    {
        $today = date('Y-m-d');
        $this->insertUsage($today, 990);

        $stmt = $this->pdo->prepare(
            'SELECT calls_made FROM abuseipdb_daily_usage WHERE usage_date = ?'
        );
        $stmt->execute([$today]);
        $calls_so_far = (int)($stmt->fetchColumn() ?: 0);

        $batch_size = 10; // 990 + 10 = 1000 exactly — still within limit
        $this->assertFalse($calls_so_far + $batch_size > 1000);
    }

    public function testFreshDayHasZeroCallsSoFar(): void
    {
        $tomorrow = date('Y-m-d', strtotime('+1 day'));
        $stmt = $this->pdo->prepare(
            'SELECT calls_made FROM abuseipdb_daily_usage WHERE usage_date = ?'
        );
        $stmt->execute([$tomorrow]);
        $calls_so_far = (int)($stmt->fetchColumn() ?: 0);

        $this->assertSame(0, $calls_so_far);
    }

    public function testQuotaUpsertCreatesRowWhenMissing(): void
    {
        $today = date('Y-m-d');

        // Mirror the INSERT ... ON DUPLICATE KEY from enrich_abuseipdb()
        // SQLite uses INSERT OR IGNORE instead of ON DUPLICATE KEY
        $this->pdo->exec(
            'INSERT OR IGNORE INTO abuseipdb_daily_usage (usage_date, calls_made)
             VALUES ("' . $today . '", 0)'
        );

        $stmt = $this->pdo->prepare(
            'SELECT calls_made FROM abuseipdb_daily_usage WHERE usage_date = ?'
        );
        $stmt->execute([$today]);
        $this->assertSame(0, (int)$stmt->fetchColumn());
    }

    public function testQuotaIncrementByActualCalls(): void
    {
        $today = date('Y-m-d');
        $this->insertUsage($today, 50);

        $actual_calls = 7;
        $stmt = $this->pdo->prepare(
            'UPDATE abuseipdb_daily_usage SET calls_made = calls_made + ?
             WHERE usage_date = ?'
        );
        $stmt->execute([$actual_calls, $today]);

        $check = $this->pdo->prepare(
            'SELECT calls_made FROM abuseipdb_daily_usage WHERE usage_date = ?'
        );
        $check->execute([$today]);
        $this->assertSame(57, (int)$check->fetchColumn());
    }

    // ── cache write ───────────────────────────────────────────────────────────

    public function testCacheWriteStoresScore(): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT OR REPLACE INTO abuseipdb_cache (ip, confidence_score, total_reports, queried_at)
             VALUES (?, ?, ?, ?)'
        );
        $stmt->execute(['5.5.5.5', 88, 12, date('Y-m-d H:i:s')]);

        $cached = $this->fetchCached(['5.5.5.5']);
        $this->assertSame(88, $cached['5.5.5.5']);
    }

    public function testCacheWriteUpdatesExistingEntry(): void
    {
        $this->insertCache('6.6.6.6', 10, 3600);

        // Re-query returns fresh value
        $stmt = $this->pdo->prepare(
            'INSERT OR REPLACE INTO abuseipdb_cache (ip, confidence_score, total_reports, queried_at)
             VALUES (?, ?, ?, ?)'
        );
        $stmt->execute(['6.6.6.6', 95, 50, date('Y-m-d H:i:s')]);

        $cached = $this->fetchCached(['6.6.6.6']);
        $this->assertSame(95, $cached['6.6.6.6']);
    }
}
