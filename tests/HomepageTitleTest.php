<?php

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The homepage <title> is owner-approved wording (IPG-116): it puts
 * "Bulk IP Geolocation" first for search. og:title and the meta description
 * were deliberately left alone, so they are pinned here too.
 */
class HomepageTitleTest extends TestCase
{
    private static function head(): string
    {
        return file_get_contents(dirname(__DIR__) . '/index.php');
    }

    public function testTitleIsTheApprovedString(): void
    {
        $this->assertStringContainsString(
            '<title>Bulk IP Geolocation &amp; ASN Lookup for Raw Logs — ip2geo.org</title>',
            self::head()
        );
    }

    public function testOgTitleAndDescriptionUnchanged(): void
    {
        $src = self::head();
        $this->assertStringContainsString('<meta property="og:title" content="ip2geo · Bulk IP lookup for raw logs" />', $src);
        $this->assertStringContainsString('<meta name="description" content="Paste any log and pull out up to 10,000 IPv4 and IPv6 addresses. Filter by country, ASN and category. Free, no signup." />', $src);
    }
}
