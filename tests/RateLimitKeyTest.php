<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/rate-limit.php';

/**
 * rate_limit_key() (IPG-21): the lookup rate limit keys IPv6 clients on their
 * /64, so one client can't take a fresh bucket per request by rotating
 * addresses inside the /64 it controls. IPv4 is keyed as is.
 */
class RateLimitKeyTest extends TestCase
{
    public function testIpv6AddressesInTheSameSlash64ShareAKey(): void
    {
        $this->assertSame(
            \rate_limit_key('2001:db8:1:2::1'),
            \rate_limit_key('2001:db8:1:2:ffff::9')
        );
        $this->assertSame('2001:db8:1:2::/64', \rate_limit_key('2001:db8:1:2::1'));
    }

    public function testIpv6AddressInAnotherSlash64GetsADifferentKey(): void
    {
        $this->assertNotSame(
            \rate_limit_key('2001:db8:1:2::1'),
            \rate_limit_key('2001:db8:1:3::1')
        );
    }

    public function testIpv6KeyIgnoresHowTheAddressIsWritten(): void
    {
        $this->assertSame(
            \rate_limit_key('2001:db8:1:2::1'),
            \rate_limit_key('2001:0DB8:0001:0002:0000:0000:0000:0001')
        );
    }

    public function testIpv4IsUnchanged(): void
    {
        $this->assertSame('198.51.100.1', \rate_limit_key('198.51.100.1'));
        $this->assertNotSame(\rate_limit_key('198.51.100.1'), \rate_limit_key('198.51.100.2'));
    }

    public function testIpv4MappedIpv6IsKeyedAsTheIpv4Address(): void
    {
        $this->assertSame('198.51.100.1', \rate_limit_key('::ffff:198.51.100.1'));
        $this->assertNotSame(\rate_limit_key('::ffff:198.51.100.1'), \rate_limit_key('::ffff:198.51.100.2'));
    }

    public function testNonIpIsReturnedAsIs(): void
    {
        $this->assertSame('not-an-ip', \rate_limit_key('not-an-ip'));
    }
}
