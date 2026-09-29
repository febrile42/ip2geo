<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Threat Reports were retired in v5.0.0 (R17): report.php is now a tiny
 * static page that returns HTTP 410 for every request, with or without a
 * token, and never touches the database.
 *
 * We include the real file (not a re-implementation) with output buffering
 * so any regression that reintroduces a DB connection or report lookup here
 * fails loudly — there is no config.php in the test environment, so a
 * mysqli_connect() or PDO call would throw/warn instead of silently passing.
 */
class ReportRetiredTest extends TestCase
{
    protected function setUp(): void
    {
        $_SERVER['HTTP_HOST'] = 'ip2geo.org';
    }

    private function renderReportPhp(): string
    {
        ob_start();
        include __DIR__ . '/../report.php';
        return ob_get_clean();
    }

    public function testNoTokenReturns410(): void
    {
        unset($_GET['token']);
        $html = $this->renderReportPhp();
        $this->assertSame(410, http_response_code());
        $this->assertStringContainsString('Threat Reports were retired in v5.0.0', $html);
        $this->assertStringContainsString('The bulk lookup is still free and right here', $html);
    }

    public function testAnyTokenQueryStringReturnsTheSame410Page(): void
    {
        $_GET['token'] = 'b3a7-does-not-matter';
        $html = $this->renderReportPhp();
        $this->assertSame(410, http_response_code());
        $this->assertStringContainsString('Threat Reports were retired in v5.0.0', $html);
        unset($_GET['token']);
    }

    public function testSourceNeverConnectsToTheDatabase(): void
    {
        // Static guard, in addition to the behavioural tests above: the
        // retired page must not even mention a DB connection path, so a
        // future edit that re-adds one is caught even if it never runs.
        $src = file_get_contents(__DIR__ . '/../report.php');
        $this->assertStringNotContainsString('mysqli_connect', $src);
        $this->assertStringNotContainsString('new PDO', $src);
        $this->assertStringNotContainsString("require __DIR__ . '/config.php'", $src);
    }
}
