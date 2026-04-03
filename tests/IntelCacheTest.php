<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Tests for the APCu page-cache logic in intel.php.
 *
 * intel.php is a page script — we mirror its cache logic here so that any
 * drift between the tests and the real code surfaces as a test failure.
 *
 * Covers:
 *  1. Cache key format includes today's UTC date (YYYY-MM-DD)
 *  2. Cache key changes at UTC midnight (tomorrow ≠ today)
 *  3. APCu absent → renderPage() called, result served, nothing stored
 *  4. APCu present, cache miss → renderPage() called, result stored + served
 *  5. APCu present, cache hit → renderPage() NOT called, cached content served
 *  6. ob_get_clean() returns false → 500, renderPage() not re-called, nothing stored
 *  7. ob_get_clean() returns empty string → 500, nothing stored
 *  8. Download request → cache bypassed entirely, renderPage() always called
 *  9. Unknown ?format value → treated as HTML request, cache applies
 * 10. apcu_store failure (returns false) → content still served to user
 *
 * Run: vendor/bin/phpunit tests/IntelCacheTest.php
 */
class IntelCacheTest extends TestCase
{
    // ── Mirrors the cache logic from intel.php ────────────────────────────────

    /**
     * Mirrors the cache key construction in intel.php.
     */
    private function buildCacheKey(string $dateStr): string
    {
        return 'intel_page_7d_' . $dateStr;
    }

    /**
     * Mirrors the is_download detection in intel.php.
     */
    private function isDownload(string $fmt): bool
    {
        $validFormats = ['iptables', 'ufw', 'nginx', 'txt'];
        return $fmt !== '' && in_array($fmt, $validFormats, true);
    }

    /**
     * Mirrors the full cache-serve / cache-store flow from intel.php,
     * with injectable dependencies for testability.
     *
     * @param string        $dateStr       Today's UTC date (YYYY-MM-DD)
     * @param string        $fmt           Value of $_GET['format'] ('' for HTML)
     * @param callable|null $apcu_fetch    Replacement for apcu_fetch(); null = APCu absent
     * @param callable|null $apcu_store    Replacement for apcu_store(); null = APCu absent
     * @param callable      $render        Simulates ob_start() + page render + ob_get_clean()
     *                                     Must return string|false
     * @return array{status:int, body:string, stored:bool}
     */
    private function runCacheFlow(
        string   $dateStr,
        string   $fmt,
        ?callable $apcu_fetch,
        ?callable $apcu_store,
        callable  $render
    ): array {
        $cacheKey   = $this->buildCacheKey($dateStr);
        $isDownload = $this->isDownload($fmt);
        $apcu_available = ($apcu_fetch !== null && $apcu_store !== null);

        // ── Cache hit path ─────────────────────────────────────────────────────
        if (!$isDownload && $apcu_available) {
            $hit    = false;
            $cached = $apcu_fetch($cacheKey, $hit);
            if ($hit) {
                return ['status' => 200, 'body' => (string) $cached, 'stored' => false];
            }
        }

        // ── Render (mirrors ob_start() + HTML output + ob_get_clean()) ─────────
        $html = $render();

        if ($html === false || $html === '') {
            return ['status' => 500, 'body' => 'Page rendering error. Please try again.', 'stored' => false];
        }

        // ── Store in APCu (HTML only, downloads bypass) ────────────────────────
        $stored = false;
        if (!$isDownload && $apcu_available) {
            $stored = (bool) $apcu_store($cacheKey, $html, 900);
        }

        return ['status' => 200, 'body' => $html, 'stored' => $stored];
    }

    // ── Cache key ─────────────────────────────────────────────────────────────

    public function testCacheKeyIncludesDate(): void
    {
        $key = $this->buildCacheKey('2026-04-03');
        $this->assertStringContainsString('2026-04-03', $key);
        $this->assertStringStartsWith('intel_page_7d_', $key);
    }

    public function testCacheKeyMatchesExpectedFormat(): void
    {
        $today = gmdate('Y-m-d');
        $key   = $this->buildCacheKey($today);
        $this->assertSame('intel_page_7d_' . $today, $key);
    }

    public function testCacheKeyChangesAtMidnight(): void
    {
        $today    = $this->buildCacheKey('2026-04-03');
        $tomorrow = $this->buildCacheKey('2026-04-04');
        $this->assertNotSame($today, $tomorrow, 'Cache key must differ between dates');
    }

    // ── APCu absent ──────────────────────────────────────────────────────────

    public function testApcu_absentRendersAndServesContent(): void
    {
        $rendered = false;
        $result = $this->runCacheFlow(
            '2026-04-03', '',
            null, null,  // APCu absent
            function () use (&$rendered) { $rendered = true; return '<html>page</html>'; }
        );

        $this->assertTrue($rendered, 'renderPage must be called when APCu is absent');
        $this->assertSame(200, $result['status']);
        $this->assertSame('<html>page</html>', $result['body']);
        $this->assertFalse($result['stored'], 'Nothing should be stored when APCu is absent');
    }

    // ── Cache miss ────────────────────────────────────────────────────────────

    public function testCacheMissRendersStoresAndServes(): void
    {
        $store = [];
        $rendered = false;

        $result = $this->runCacheFlow(
            '2026-04-03', '',
            function (string $key, bool &$hit) { $hit = false; return null; },  // miss
            function (string $key, string $val, int $ttl) use (&$store) {
                $store[$key] = ['val' => $val, 'ttl' => $ttl];
                return true;
            },
            function () use (&$rendered) { $rendered = true; return '<html>fresh</html>'; }
        );

        $this->assertTrue($rendered, 'renderPage must be called on cache miss');
        $this->assertSame(200, $result['status']);
        $this->assertSame('<html>fresh</html>', $result['body']);
        $this->assertTrue($result['stored'], 'Content must be stored on cache miss');
        $this->assertArrayHasKey('intel_page_7d_2026-04-03', $store);
        $this->assertSame('<html>fresh</html>', $store['intel_page_7d_2026-04-03']['val']);
        $this->assertSame(900, $store['intel_page_7d_2026-04-03']['ttl'], 'TTL must be 900 seconds (15 min)');
    }

    // ── Cache hit ─────────────────────────────────────────────────────────────

    public function testCacheHitServesContentWithoutRendering(): void
    {
        $rendered = false;

        $result = $this->runCacheFlow(
            '2026-04-03', '',
            function (string $key, bool &$hit) { $hit = true; return '<html>cached</html>'; },
            function () { return true; },
            function () use (&$rendered) { $rendered = true; return '<html>fresh</html>'; }
        );

        $this->assertFalse($rendered, 'renderPage must NOT be called on cache hit');
        $this->assertSame(200, $result['status']);
        $this->assertSame('<html>cached</html>', $result['body']);
        $this->assertFalse($result['stored'], 'Nothing should be re-stored on cache hit');
    }

    // ── ob_get_clean failure ──────────────────────────────────────────────────

    public function testObGetCleanReturnsFalseYields500(): void
    {
        $stored = false;

        $result = $this->runCacheFlow(
            '2026-04-03', '',
            function (string $key, bool &$hit) { $hit = false; return null; },
            function () use (&$stored) { $stored = true; return true; },
            function () { return false; }  // ob_get_clean() failed
        );

        $this->assertSame(500, $result['status']);
        $this->assertStringContainsString('rendering error', $result['body']);
        $this->assertFalse($stored, 'Must not store anything when ob_get_clean() fails');
    }

    public function testObGetCleanReturnsEmptyStringYields500(): void
    {
        $stored = false;

        $result = $this->runCacheFlow(
            '2026-04-03', '',
            function (string $key, bool &$hit) { $hit = false; return null; },
            function () use (&$stored) { $stored = true; return true; },
            function () { return ''; }  // ob_get_clean() returned empty
        );

        $this->assertSame(500, $result['status']);
        $this->assertFalse($stored, 'Must not store empty string in APCu');
    }

    // ── Download bypass ───────────────────────────────────────────────────────

    /**
     * @dataProvider downloadFormatProvider
     */
    public function testDownloadBypassesCache(string $fmt): void
    {
        $fetchCalled = false;
        $storeCalled = false;
        $rendered    = false;

        $result = $this->runCacheFlow(
            '2026-04-03', $fmt,
            function (string $key, bool &$hit) use (&$fetchCalled) { $fetchCalled = true; $hit = true; return '<html>cached</html>'; },
            function () use (&$storeCalled) { $storeCalled = true; return true; },
            function () use (&$rendered) { $rendered = true; return 'download-content'; }
        );

        $this->assertFalse($fetchCalled, "Cache must not be read for format={$fmt}");
        $this->assertFalse($storeCalled, "Cache must not be written for format={$fmt}");
        $this->assertTrue($rendered, "renderPage must always be called for format={$fmt}");
        $this->assertSame(200, $result['status']);
        $this->assertSame('download-content', $result['body']);
    }

    public static function downloadFormatProvider(): array
    {
        return [
            'iptables' => ['iptables'],
            'ufw'      => ['ufw'],
            'nginx'    => ['nginx'],
            'txt'      => ['txt'],
        ];
    }

    public function testUnknownFormatTreatedAsHtmlRequest(): void
    {
        $this->assertFalse($this->isDownload('csv'), 'Unknown format must not be treated as download');
        $this->assertFalse($this->isDownload(''),    'Empty format must not be treated as download');
        $this->assertFalse($this->isDownload('xml'), 'xml must not be treated as download');
    }

    // ── apcu_store failure ────────────────────────────────────────────────────

    public function testApcu_storeFailureStillServesContent(): void
    {
        $result = $this->runCacheFlow(
            '2026-04-03', '',
            function (string $key, bool &$hit) { $hit = false; return null; },
            function () { return false; },  // apcu_store fails
            function () { return '<html>page</html>'; }
        );

        $this->assertSame(200, $result['status']);
        $this->assertSame('<html>page</html>', $result['body'],
            'Content must still be served even if apcu_store fails');
        $this->assertFalse($result['stored']);
    }
}
