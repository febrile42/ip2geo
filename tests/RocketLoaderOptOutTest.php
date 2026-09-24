<?php

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Cloudflare Rocket Loader (on for the ip2geo.org zone) rewrites script tags
 * and runs them later and out of order. On staging that left window.extractIps
 * undefined, so the Phase 2 workbench silently fell back to the plain form POST,
 * and it would reorder R3's fragment-strip vs the Umami tracker. Every script
 * tag must opt out.
 */
class RocketLoaderOptOutTest extends TestCase
{
    public static function pages(): array
    {
        return [['index.php'], ['includes/page-chrome.php']];
    }

    /** @dataProvider pages */
    public function testEveryScriptTagOptsOutOfRocketLoader(string $page): void
    {
        $src = file_get_contents(dirname(__DIR__) . '/' . $page);
        preg_match_all('/<script\b[^>]*>/i', $src, $m);
        $this->assertNotEmpty($m[0]);
        foreach ($m[0] as $tag) {
            $this->assertStringContainsString('data-cfasync="false"', $tag, "$page: $tag");
        }
    }
}
