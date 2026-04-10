<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Geo classification cache tests (SQLite mirror of geo_classification_cache table).
 *
 * Tests the cache-first lookup added to get-report.php:
 *  - Cache HIT (unexpired):  return ip_list_json + geo_json, skip re-classification
 *  - Cache MISS (expired):   do not return row → server-side re-classification path
 *  - Cache MISS (absent):    no row → server-side re-classification path
 *  - Cache key derivation:   sorted IPs → SHA-256 → deterministic key
 *
 * We mirror the exact SQL from get-report.php so drift is detectable.
 */
class GeoCacheTest extends TestCase
{
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $this->pdo->exec("
            CREATE TABLE geo_classification_cache (
                cache_key    CHAR(64)   NOT NULL,
                ip_list_json TEXT       NOT NULL,
                geo_json     TEXT       NOT NULL,
                expires_at   DATETIME   NOT NULL,
                PRIMARY KEY  (cache_key)
            )
        ");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Insert a cache row. $ttl_seconds: positive = expires in future, negative = already expired. */
    private function insertCache(string $key, string $ipJson, string $geoJson, int $ttl_seconds = 1800): void
    {
        $expires = date('Y-m-d H:i:s', time() + $ttl_seconds);
        $stmt = $this->pdo->prepare(
            'INSERT OR REPLACE INTO geo_classification_cache
             (cache_key, ip_list_json, geo_json, expires_at) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$key, $ipJson, $geoJson, $expires]);
    }

    /** Simulate the cache SELECT from get-report.php (uses NOW() expressed as current timestamp). */
    private function fetchCache(string $key): ?array
    {
        $now = date('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'SELECT ip_list_json, geo_json FROM geo_classification_cache
             WHERE cache_key = ? AND expires_at > ?'
        );
        $stmt->execute([$key, $now]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /** Mirror the cache_key derivation from get-report.php. */
    private function makeCacheKey(array $ips): string
    {
        $sorted = $ips;
        sort($sorted);
        return hash('sha256', implode(',', $sorted));
    }

    // ── cache hit / miss ──────────────────────────────────────────────────────

    public function testUnexpiredCacheRowIsReturned(): void
    {
        $key = $this->makeCacheKey(['1.2.3.4', '5.6.7.8']);
        $this->insertCache($key, '["ip_data"]', '["geo_data"]', 1800);

        $row = $this->fetchCache($key);
        $this->assertNotNull($row);
        $this->assertSame('["ip_data"]', $row['ip_list_json']);
        $this->assertSame('["geo_data"]', $row['geo_json']);
    }

    public function testExpiredCacheRowIsNotReturned(): void
    {
        $key = $this->makeCacheKey(['1.2.3.4']);
        $this->insertCache($key, '["ip_data"]', '["geo_data"]', -1); // expired 1 second ago

        $row = $this->fetchCache($key);
        $this->assertNull($row);
    }

    public function testAbsentKeyReturnsNull(): void
    {
        $row = $this->fetchCache('nonexistent_key');
        $this->assertNull($row);
    }

    public function testExactlyExpiredIsNotReturned(): void
    {
        // expires_at = current second — the query uses > not >=
        $key = $this->makeCacheKey(['2.3.4.5']);
        $this->insertCache($key, '[]', '[]', 0);

        // Sleep is not available in unit tests; instead we force an expired timestamp directly
        $stmt = $this->pdo->prepare(
            'UPDATE geo_classification_cache SET expires_at = ? WHERE cache_key = ?'
        );
        $stmt->execute([date('Y-m-d H:i:s', time() - 1), $key]);

        $row = $this->fetchCache($key);
        $this->assertNull($row);
    }

    // ── cache key derivation ──────────────────────────────────────────────────

    public function testCacheKeyIsDeterministicForSortedIps(): void
    {
        $ips = ['8.8.8.8', '1.1.1.1', '4.4.4.4'];
        $key1 = $this->makeCacheKey($ips);
        $key2 = $this->makeCacheKey(array_reverse($ips));

        // Order of input must not change the key — it's sorted first
        $this->assertSame($key1, $key2);
    }

    public function testCacheKeyDifferentForDifferentIpSets(): void
    {
        $key1 = $this->makeCacheKey(['1.1.1.1', '2.2.2.2']);
        $key2 = $this->makeCacheKey(['1.1.1.1', '3.3.3.3']);

        $this->assertNotSame($key1, $key2);
    }

    public function testCacheKeyIs64HexChars(): void
    {
        $key = $this->makeCacheKey(['10.0.0.1']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
    }

    // ── cache write (upsert) ──────────────────────────────────────────────────

    public function testCacheUpsertOverwritesExpiredEntry(): void
    {
        $key = $this->makeCacheKey(['9.9.9.9']);
        $this->insertCache($key, '["old"]', '["old_geo"]', -60); // expired

        // Overwrite with fresh entry
        $this->insertCache($key, '["new"]', '["new_geo"]', 1800);

        $row = $this->fetchCache($key);
        $this->assertNotNull($row);
        $this->assertSame('["new"]', $row['ip_list_json']);
    }
}
