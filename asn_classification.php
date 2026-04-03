<?php
/**
 * ASN classification array and keyword fallback.
 *
 * classify_asn(string $asn_number, string $asn_org): string
 *   Returns one of: 'scanning' | 'cloud' | 'vpn' | 'residential' | 'unknown'
 *
 * The $known_asns array is the authoritative source. For ASNs not listed,
 * keyword_classify() provides a best-effort fallback from the org name.
 *
 * Maintenance: the monthly update-db.yml workflow diffs this array against the
 * Spamhaus ASN-DROP list and opens a draft PR with any gaps. Never auto-merged.
 */

// Format: 'AS{number}' => 'category'
// Categories: scanning | cloud | vpn | residential
// 'global' declaration ensures this reaches the global symbol table even when
// the file is required from inside a function (e.g. Composer's files autoloader,
// PHPUnit's class loader). Without it, the variable would be local to that scope.
global $known_asns;
$known_asns = [
    // --- Scanning / cloud exit nodes (Shodan, Censys, research scanners) ---
    'AS20473'  => 'scanning',  // Vultr / Choopa
    'AS16276'  => 'scanning',  // OVH
    'AS14061'  => 'scanning',  // DigitalOcean
    'AS24940'  => 'scanning',  // Hetzner
    'AS8075'   => 'cloud',     // Microsoft Azure
    'AS16509'  => 'cloud',     // Amazon AWS (EC2)
    'AS14618'  => 'cloud',     // Amazon AWS (us-east-1 legacy)
    'AS15169'  => 'cloud',     // Google Cloud
    'AS396982' => 'cloud',     // Google Cloud (newer)
    'AS19527'  => 'cloud',     // Google Cloud (GFE)
    'AS13335'  => 'cloud',     // Cloudflare
    'AS209'    => 'cloud',     // CenturyLink / Lumen Cloud
    'AS6939'   => 'cloud',     // Hurricane Electric
    'AS46484'  => 'scanning',  // Censys scanning infrastructure
    'AS398705' => 'scanning',  // Censys
    'AS30083'  => 'scanning',  // Shodan

    // --- Commercial VPN / proxy providers ---
    'AS9009'   => 'vpn',       // M247 (used by many VPN providers)
    'AS60068'  => 'vpn',       // Datacamp / used by VPNs
    'AS34665'  => 'vpn',       // Petersburg Internet Network (VPN exit)
    'AS13213'  => 'vpn',       // UK-2 Ltd / NordVPN
    'AS202425' => 'vpn',       // IP Volume (VPN/proxy)
    'AS174'    => 'vpn',       // Cogent (large transit, used by proxy services)
    'AS62240'  => 'vpn',       // Clouvider (VPN hosting)
    'AS199559' => 'vpn',       // Private Internet Access (PIA)
    'AS36352'  => 'vpn',       // ColoCrossing (bulk VPN/proxy hosting)
    'AS40676'  => 'vpn',       // Psychz Networks (VPN/proxy)
    'AS49981'  => 'vpn',       // WorldStream (VPN hosting)
    'AS209854' => 'vpn',       // Advin Services (residential proxy)
    'AS4766'   => 'scanning',  // Korea Telecom (heavy scanning source)
    'AS9121'   => 'scanning',  // Turk Telekom (heavy scanning source)

    // --- Tor exit infrastructure ---
    'AS60729'  => 'scanning',  // Zwiebelfreunde e.V. (185.220.101.x Tor exits)
    'AS205100' => 'scanning',  // Freiheitsfoo e.V. (185.220.100.x Tor exits)
    'AS208323' => 'scanning',  // Artikel 10 e.V. (Tor exits)
    'AS200052' => 'scanning',  // Tor Exit AS (torservers.net)

    // --- Known high-volume scanning sources ---
    'AS4134'   => 'scanning',  // China Telecom (Chinanet)
    'AS4837'   => 'scanning',  // China Unicom
    'AS58224'  => 'scanning',  // Iran Telecommunication
    'AS44217'  => 'scanning',  // RIPE NCC (research scanning)
    'AS51167'  => 'scanning',  // Contabo (frequently abused)

    // --- Residential / consumer ISPs (well-known, low suspicion) ---
    'AS7922'   => 'residential', // Comcast
    'AS20115'  => 'residential', // Charter / Spectrum
    'AS7018'   => 'residential', // AT&T
    'AS701'    => 'residential', // Verizon
    'AS1239'   => 'residential', // Sprint
    'AS5650'   => 'residential', // Frontier Communications
    'AS33363'  => 'residential', // BrightHouse / Charter legacy
];

/**
 * Keyword fallback for ASNs not in $known_asns.
 * Returns a category string or 'unknown'.
 */
function keyword_classify(string $org): string {
    $org_lower = strtolower($org);

    // VPN / proxy signals (no leading word-boundary: catches NordVPN, TunnelBear, etc.)
    if (preg_match('/(vpn|proxy|privacy|anonymi[sz]|tunnel|socks|residential.?prox)/i', $org)) {
        return 'vpn';
    }

    // Scanning / cloud signals (trailing \b only: catches FastHosting, but not 'cloudxyz')
    if (preg_match('/(hosting|cloud|data.?cent(er|re)|coloc(ation)?|server|vps|dedicated|linode|vultr|ovh|hetzner|digitalocean|contabo|aws|azure|gcp|fastly|akamai|cdn)\b/i', $org)) {
        return 'cloud';
    }

    // Residential / ISP signals (trailing \b only: catches CityFiber, but not 'fiberx')
    if (preg_match('/(telecom|telco|broadband|cable|dsl|fiber|isp|internet.?service|mobile|wireless|residential|consumer)\b/i', $org)) {
        return 'residential';
    }

    return 'unknown';
}

/**
 * Classify an IP's ASN.
 *
 * @param string $asn_number  e.g. "15169" (no "AS" prefix from DB column)
 * @param string $asn_org     e.g. "GOOGLE" (autonomous_system_org from DB)
 * @return string  'scanning' | 'cloud' | 'vpn' | 'residential' | 'unknown'
 */
function classify_asn(string $asn_number, string $asn_org): string {
    global $known_asns;

    $key = 'AS' . $asn_number;
    if (isset($known_asns[$key])) {
        return $known_asns[$key];
    }

    return keyword_classify($asn_org);
}
