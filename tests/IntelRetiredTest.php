<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The Community Block List was retired in v5.0.0 (IPG-23): intel.php returns
 * HTTP 410 for every request, including the old ?format= download URLs, and
 * never touches the database. Includes the real file, like ReportRetiredTest.
 */
class IntelRetiredTest extends TestCase
{
    protected function setUp(): void
    {
        $_SERVER['HTTP_HOST'] = 'ip2geo.org';
    }

    private function renderIntelPhp(): string
    {
        ob_start();
        include __DIR__ . '/../intel.php';
        return ob_get_clean();
    }

    public function testPageReturns410(): void
    {
        unset($_GET['format']);
        $html = $this->renderIntelPhp();
        $this->assertSame(410, http_response_code());
        $this->assertStringContainsString('The Community Block List was retired in v5.0.0', $html);
        $this->assertStringNotContainsString('Check back soon', $html);
    }

    public function testOldDownloadUrlReturnsTheSame410Page(): void
    {
        $_GET['format'] = 'iptables';
        $html = $this->renderIntelPhp();
        $this->assertSame(410, http_response_code());
        $this->assertStringContainsString('The Community Block List was retired in v5.0.0', $html);
        $this->assertStringNotContainsString('iptables', $html);
        unset($_GET['format']);
    }

    public function testSourceNeverConnectsToTheDatabase(): void
    {
        $src = file_get_contents(__DIR__ . '/../intel.php');
        $this->assertStringNotContainsString('mysqli', $src);
        $this->assertStringNotContainsString('new PDO', $src);
        $this->assertStringNotContainsString('config.php', $src);
    }
}
