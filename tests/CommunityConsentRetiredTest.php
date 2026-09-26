<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * community-consent.php was retired in v5.0.0 (IPG-10 S4): it returns 410
 * for every request and never touches the database. Includes the real file,
 * like ReportRetiredTest does for report.php.
 */
class CommunityConsentRetiredTest extends TestCase
{
    private function run410(string $method): string
    {
        $_SERVER['REQUEST_METHOD'] = $method;
        $_POST = ['token' => 'b3a7-does-not-matter', 'consent' => '1'];
        ob_start();
        include __DIR__ . '/../community-consent.php';
        $out = ob_get_clean();
        $_POST = [];
        return $out;
    }

    public function testPostReturns410(): void
    {
        $this->assertSame('{"error":"gone"}', $this->run410('POST'));
        $this->assertSame(410, http_response_code());
    }

    public function testGetReturns410(): void
    {
        $this->assertSame('{"error":"gone"}', $this->run410('GET'));
        $this->assertSame(410, http_response_code());
    }

    public function testSourceNeverConnectsToTheDatabase(): void
    {
        $src = file_get_contents(__DIR__ . '/../community-consent.php');
        $this->assertStringNotContainsString('config.php', $src);
        $this->assertStringNotContainsString('mysqli', $src);
        $this->assertStringNotContainsString('PDO', $src);
    }
}
