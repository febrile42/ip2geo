<?php

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The MaxMind credit uses the attribution example from the GeoLite EULA §3
 * and carries the CC BY-SA 4.0 licence notice that CC BY-SA §3(a) requires
 * (IPG-146). External footer links open with rel="noopener".
 */
class FooterAttributionTest extends TestCase
{
    private static function footer(): string
    {
        return file_get_contents(dirname(__DIR__) . '/includes/footer.php');
    }

    public function testMaxMindAttributionWithLicenceNotice(): void
    {
        $this->assertStringContainsString(
            '<li>This product includes GeoLite Data created by MaxMind, available from '
            . '<a href="https://www.maxmind.com" target="_blank" rel="noopener">https://www.maxmind.com</a>, '
            . 'licensed under <a href="https://creativecommons.org/licenses/by-sa/4.0/" target="_blank" rel="noopener">CC BY-SA 4.0</a>.</li>',
            self::footer()
        );
    }

    public function testExternalLinksUseNoopener(): void
    {
        preg_match_all('/<a\s[^>]*href="https?:\/\/[^"]*"[^>]*>/', self::footer(), $m);
        $this->assertNotEmpty($m[0]);
        foreach ($m[0] as $tag) {
            $this->assertStringContainsString('rel="noopener"', $tag, $tag);
        }
    }
}
