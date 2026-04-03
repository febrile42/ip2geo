<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

// asn_classification.php defines $known_asns (global) and three functions.
// Including it here loads both, so tests have the full production data.
require_once __DIR__ . '/../asn_classification.php';

/**
 * Tests for classify_asn() and keyword_classify().
 *
 * Covers:
 *  - known ASN lookups (spot-checks on real entries)
 *  - keyword fallback paths for each category
 *  - unknown fallback when nothing matches
 *  - edge cases: empty strings, numeric-only ASN, unusual casing
 */
class AsnClassificationTest extends TestCase
{
    // ── classify_asn — known-ASN lookups ──────────────────────────────────────

    public function testGoogleCloudIsCloud(): void
    {
        $this->assertSame('cloud', classify_asn('15169', 'GOOGLE'));
    }

    public function testDigitalOceanIsScanning(): void
    {
        $this->assertSame('scanning', classify_asn('14061', 'DIGITALOCEAN-ASN'));
    }

    public function testM247IsVpn(): void
    {
        $this->assertSame('vpn', classify_asn('9009', 'M247 Ltd'));
    }

    public function testComcastIsResidential(): void
    {
        $this->assertSame('residential', classify_asn('7922', 'Comcast Cable'));
    }

    public function testAWSIsCloud(): void
    {
        $this->assertSame('cloud', classify_asn('16509', 'Amazon.com, Inc.'));
    }

    public function testChinaTelecomIsScanning(): void
    {
        $this->assertSame('scanning', classify_asn('4134', 'CHINANET-BACKBONE'));
    }

    public function testContaboIsScanning(): void
    {
        $this->assertSame('scanning', classify_asn('51167', 'Contabo GmbH'));
    }

    // ── classify_asn — unknown ASN falls back to keyword ──────────────────────

    public function testUnknownAsnWithHostingOrgIsCloud(): void
    {
        $this->assertSame('cloud', classify_asn('99999', 'FastHosting Ltd'));
    }

    public function testUnknownAsnWithVpnOrgIsVpn(): void
    {
        $this->assertSame('vpn', classify_asn('99998', 'BestVPN Services Inc'));
    }

    public function testUnknownAsnWithTelecomOrgIsResidential(): void
    {
        $this->assertSame('residential', classify_asn('99997', 'Regional Telecom Inc'));
    }

    public function testUnknownAsnWithNoKeywordMatchIsUnknown(): void
    {
        $this->assertSame('unknown', classify_asn('99996', 'XYZ Corp'));
    }

    public function testEmptyAsnNumberAndEmptyOrgIsUnknown(): void
    {
        $this->assertSame('unknown', classify_asn('', ''));
    }

    // ── keyword_classify ──────────────────────────────────────────────────────

    public function testKeywordVpn(): void
    {
        $this->assertSame('vpn', keyword_classify('NordVPN GmbH'));
    }

    public function testKeywordProxy(): void
    {
        $this->assertSame('vpn', keyword_classify('residential proxy solutions'));
    }

    public function testKeywordAnonymizer(): void
    {
        $this->assertSame('vpn', keyword_classify('Anonymizer.com Inc'));
    }

    public function testKeywordTunnel(): void
    {
        $this->assertSame('vpn', keyword_classify('TunnelBear LLC'));
    }

    public function testKeywordDatacenter(): void
    {
        $this->assertSame('cloud', keyword_classify('Acme Datacenter LLC'));
    }

    public function testKeywordDataCentreSpelling(): void
    {
        $this->assertSame('cloud', keyword_classify('London Data Centre Ltd'));
    }

    public function testKeywordVps(): void
    {
        $this->assertSame('cloud', keyword_classify('Cheap VPS Hosting'));
    }

    public function testKeywordLinode(): void
    {
        $this->assertSame('cloud', keyword_classify('Linode LLC'));
    }

    public function testKeywordBroadband(): void
    {
        $this->assertSame('residential', keyword_classify('SomeTown Broadband'));
    }

    public function testKeywordFiber(): void
    {
        $this->assertSame('residential', keyword_classify('CityFiber Network'));
    }

    public function testKeywordMobile(): void
    {
        $this->assertSame('residential', keyword_classify('T-Mobile USA'));
    }

    public function testNoKeywordMatchReturnsUnknown(): void
    {
        $this->assertSame('unknown', keyword_classify(''));
    }

    public function testNoKeywordMatchArbitraryString(): void
    {
        $this->assertSame('unknown', keyword_classify('Widgets International'));
    }

    public function testKeywordMatchIsCaseInsensitive(): void
    {
        $this->assertSame('cloud', keyword_classify('HETZNER ONLINE GMBH'));
    }
}
