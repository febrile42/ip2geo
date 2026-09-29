<?php

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Regression: index.php and api/lookup.php never load Composer themselves, and
 * PHPUnit's bootstrap does, so an in-process test can't see a missing
 * autoloader. This runs a fresh PHP process that only requires
 * includes/lookup.php, the way a real page does.
 */
class LookupAutoloadTest extends TestCase
{
    public function testLookupWorksWithoutComposerBootstrap(): void
    {
        $root = dirname(__DIR__);
        $code = 'require ' . var_export($root . '/includes/lookup.php', true) . ';'
              . '$r = lookup_ips(["81.2.69.160"], '
              . var_export($root . '/tests/fixtures/mmdb/GeoIP2-City-Test.mmdb', true) . ', '
              . var_export($root . '/tests/fixtures/mmdb/GeoLite2-ASN-Test.mmdb', true) . ');'
              . 'echo json_encode($r);';
        $out = shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>&1');
        $this->assertStringNotContainsString('not found', (string) $out);
        $this->assertStringContainsString('GB', (string) $out);
    }
}
