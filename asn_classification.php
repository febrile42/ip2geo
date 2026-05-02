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
 * Maintenance: the monthly sync-spamhaus.yml workflow regenerates the auto-sync
 * block (between the BEGIN/END markers below) from the Spamhaus ASN-DROP list,
 * commits the result directly to develop, and lets staging redeploy. Manual
 * entries above the BEGIN marker are sacrosanct — the workflow never touches
 * them. To override a Spamhaus-classified ASN, move its entry out of the
 * auto-sync block into the appropriate manual section.
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

    // --- BEGIN AUTO-SYNC SPAMHAUS ASN-DROP (do not hand-edit) ---
    // Synced monthly from https://www.spamhaus.org/drop/asndrop.json by
    // .github/workflows/sync-spamhaus.yml. To override an entry's classification,
    // move it OUT of this block into the appropriate manual section above.
    // Last sync: 2026-05-02
    'AS245' => 'scanning',
    'AS2601' => 'scanning',
    'AS2702' => 'scanning',
    'AS3563' => 'scanning',
    'AS5065' => 'scanning',
    'AS6060' => 'scanning',
    'AS6186' => 'scanning',
    'AS6207' => 'scanning',
    'AS6729' => 'scanning',
    'AS7411' => 'scanning',
    'AS7857' => 'scanning',
    'AS7907' => 'scanning',
    'AS8649' => 'scanning',
    'AS9164' => 'scanning',
    'AS11938' => 'scanning',
    'AS13875' => 'scanning',
    'AS17447' => 'scanning',
    'AS17612' => 'scanning',
    'AS17994' => 'scanning',
    'AS23865' => 'scanning',
    'AS24426' => 'scanning',
    'AS24544' => 'scanning',
    'AS24567' => 'scanning',
    'AS25288' => 'scanning',
    'AS25862' => 'scanning',
    'AS26173' => 'scanning',
    'AS26561' => 'scanning',
    'AS26701' => 'scanning',
    'AS30490' => 'scanning',
    'AS31561' => 'scanning',
    'AS33042' => 'scanning',
    'AS33993' => 'scanning',
    'AS34985' => 'scanning',
    'AS35478' => 'scanning',
    'AS35624' => 'scanning',
    'AS35830' => 'scanning',
    'AS36680' => 'scanning',
    'AS37707' => 'scanning',
    'AS38149' => 'scanning',
    'AS38337' => 'scanning',
    'AS38871' => 'scanning',
    'AS38946' => 'scanning',
    'AS39600' => 'scanning',
    'AS39720' => 'scanning',
    'AS40193' => 'scanning',
    'AS40665' => 'scanning',
    'AS40963' => 'scanning',
    'AS41155' => 'scanning',
    'AS42192' => 'scanning',
    'AS42397' => 'scanning',
    'AS42419' => 'scanning',
    'AS42505' => 'scanning',
    'AS42881' => 'scanning',
    'AS43444' => 'scanning',
    'AS43463' => 'scanning',
    'AS43481' => 'scanning',
    'AS43613' => 'scanning',
    'AS43668' => 'scanning',
    'AS43743' => 'scanning',
    'AS44208' => 'scanning',
    'AS44382' => 'scanning',
    'AS44386' => 'scanning',
    'AS44559' => 'scanning',
    'AS44801' => 'scanning',
    'AS46664' => 'scanning',
    'AS47105' => 'scanning',
    'AS47890' => 'scanning',
    'AS47893' => 'scanning',
    'AS47926' => 'scanning',
    'AS47945' => 'scanning',
    'AS48090' => 'scanning',
    'AS48198' => 'scanning',
    'AS48589' => 'scanning',
    'AS48693' => 'scanning',
    'AS49418' => 'scanning',
    'AS49443' => 'scanning',
    'AS49581' => 'scanning',
    'AS50236' => 'scanning',
    'AS51045' => 'scanning',
    'AS51124' => 'scanning',
    'AS51381' => 'scanning',
    'AS51396' => 'scanning',
    'AS51447' => 'scanning',
    'AS51511' => 'scanning',
    'AS51722' => 'scanning',
    'AS53958' => 'scanning',
    'AS54497' => 'scanning',
    'AS54801' => 'scanning',
    'AS55154' => 'scanning',
    'AS55748' => 'scanning',
    'AS55933' => 'scanning',
    'AS56291' => 'scanning',
    'AS56362' => 'scanning',
    'AS56584' => 'scanning',
    'AS56873' => 'scanning',
    'AS57100' => 'scanning',
    'AS57415' => 'scanning',
    'AS57509' => 'scanning',
    'AS57523' => 'scanning',
    'AS58854' => 'scanning',
    'AS59425' => 'scanning',
    'AS59651' => 'scanning',
    'AS59683' => 'scanning',
    'AS60223' => 'scanning',
    'AS60842' => 'scanning',
    'AS60974' => 'scanning',
    'AS61432' => 'scanning',
    'AS61879' => 'scanning',
    'AS62206' => 'scanning',
    'AS62380' => 'scanning',
    'AS62864' => 'scanning',
    'AS63881' => 'scanning',
    'AS131750' => 'scanning',
    'AS131831' => 'scanning',
    'AS132574' => 'scanning',
    'AS132827' => 'scanning',
    'AS132930' => 'scanning',
    'AS133320' => 'scanning',
    'AS133488' => 'scanning',
    'AS133668' => 'scanning',
    'AS133692' => 'scanning',
    'AS133731' => 'scanning',
    'AS133994' => 'scanning',
    'AS134121' => 'scanning',
    'AS134176' => 'scanning',
    'AS134196' => 'scanning',
    'AS135271' => 'scanning',
    'AS135752' => 'scanning',
    'AS136367' => 'scanning',
    'AS136923' => 'scanning',
    'AS137156' => 'scanning',
    'AS137508' => 'scanning',
    'AS138687' => 'scanning',
    'AS138749' => 'scanning',
    'AS138808' => 'scanning',
    'AS138915' => 'scanning',
    'AS138968' => 'scanning',
    'AS140125' => 'scanning',
    'AS140129' => 'scanning',
    'AS140155' => 'scanning',
    'AS140184' => 'scanning',
    'AS140208' => 'scanning',
    'AS140666' => 'scanning',
    'AS140787' => 'scanning',
    'AS140869' => 'scanning',
    'AS140941' => 'scanning',
    'AS141333' => 'scanning',
    'AS141567' => 'scanning',
    'AS141803' => 'scanning',
    'AS141835' => 'scanning',
    'AS141836' => 'scanning',
    'AS141853' => 'scanning',
    'AS141875' => 'scanning',
    'AS142002' => 'scanning',
    'AS142062' => 'scanning',
    'AS142430' => 'scanning',
    'AS142519' => 'scanning',
    'AS142622' => 'scanning',
    'AS146887' => 'scanning',
    'AS147211' => 'scanning',
    'AS147287' => 'scanning',
    'AS147291' => 'scanning',
    'AS149181' => 'scanning',
    'AS149196' => 'scanning',
    'AS149197' => 'scanning',
    'AS149208' => 'scanning',
    'AS149242' => 'scanning',
    'AS149286' => 'scanning',
    'AS150030' => 'scanning',
    'AS150036' => 'scanning',
    'AS150082' => 'scanning',
    'AS150091' => 'scanning',
    'AS150100' => 'scanning',
    'AS150101' => 'scanning',
    'AS150102' => 'scanning',
    'AS150604' => 'scanning',
    'AS150813' => 'scanning',
    'AS150860' => 'scanning',
    'AS151604' => 'scanning',
    'AS152149' => 'scanning',
    'AS152170' => 'scanning',
    'AS152192' => 'scanning',
    'AS152194' => 'scanning',
    'AS152327' => 'scanning',
    'AS152485' => 'scanning',
    'AS152486' => 'scanning',
    'AS154177' => 'scanning',
    'AS154206' => 'scanning',
    'AS197450' => 'scanning',
    'AS197555' => 'scanning',
    'AS198071' => 'scanning',
    'AS198571' => 'scanning',
    'AS198926' => 'scanning',
    'AS198953' => 'scanning',
    'AS198981' => 'scanning',
    'AS199052' => 'scanning',
    'AS199420' => 'scanning',
    'AS199467' => 'scanning',
    'AS199639' => 'scanning',
    'AS199785' => 'scanning',
    'AS200010' => 'scanning',
    'AS200130' => 'scanning',
    'AS200373' => 'scanning',
    'AS200593' => 'scanning',
    'AS200699' => 'scanning',
    'AS200733' => 'scanning',
    'AS201249' => 'scanning',
    'AS201292' => 'scanning',
    'AS201380' => 'scanning',
    'AS201572' => 'scanning',
    'AS201626' => 'scanning',
    'AS201738' => 'scanning',
    'AS201813' => 'scanning',
    'AS201836' => 'scanning',
    'AS202144' => 'scanning',
    'AS202171' => 'scanning',
    'AS202267' => 'scanning',
    'AS202302' => 'scanning',
    'AS202306' => 'scanning',
    'AS202318' => 'scanning',
    'AS202383' => 'scanning',
    'AS202388' => 'scanning',
    'AS202412' => 'scanning',
    'AS202481' => 'scanning',
    'AS203120' => 'scanning',
    'AS203273' => 'scanning',
    'AS203861' => 'scanning',
    'AS203950' => 'scanning',
    'AS203999' => 'scanning',
    'AS204330' => 'scanning',
    'AS204428' => 'scanning',
    'AS204490' => 'scanning',
    'AS204502' => 'scanning',
    'AS204552' => 'scanning',
    'AS204610' => 'scanning',
    'AS204794' => 'scanning',
    'AS204868' => 'scanning',
    'AS204872' => 'scanning',
    'AS205083' => 'scanning',
    'AS205301' => 'scanning',
    'AS205486' => 'scanning',
    'AS205745' => 'scanning',
    'AS205759' => 'scanning',
    'AS205770' => 'scanning',
    'AS205775' => 'scanning',
    'AS205884' => 'scanning',
    'AS206005' => 'scanning',
    'AS206127' => 'scanning',
    'AS206305' => 'scanning',
    'AS206340' => 'scanning',
    'AS206413' => 'scanning',
    'AS206535' => 'scanning',
    'AS206560' => 'scanning',
    'AS206582' => 'scanning',
    'AS206590' => 'scanning',
    'AS206623' => 'scanning',
    'AS206644' => 'scanning',
    'AS206728' => 'scanning',
    'AS206744' => 'scanning',
    'AS206750' => 'scanning',
    'AS206831' => 'scanning',
    'AS207088' => 'scanning',
    'AS207184' => 'scanning',
    'AS207566' => 'scanning',
    'AS207812' => 'scanning',
    'AS207957' => 'scanning',
    'AS207986' => 'scanning',
    'AS208137' => 'scanning',
    'AS208198' => 'scanning',
    'AS208241' => 'scanning',
    'AS208312' => 'scanning',
    'AS208317' => 'scanning',
    'AS208525' => 'scanning',
    'AS208846' => 'scanning',
    'AS209121' => 'scanning',
    'AS209274' => 'scanning',
    'AS209373' => 'scanning',
    'AS209375' => 'scanning',
    'AS209396' => 'scanning',
    'AS209605' => 'scanning',
    'AS209847' => 'scanning',
    'AS209868' => 'scanning',
    'AS209883' => 'scanning',
    'AS209889' => 'scanning',
    'AS209896' => 'scanning',
    'AS209944' => 'scanning',
    'AS209961' => 'scanning',
    'AS209963' => 'scanning',
    'AS209982' => 'scanning',
    'AS210240' => 'scanning',
    'AS210316' => 'scanning',
    'AS210530' => 'scanning',
    'AS210558' => 'scanning',
    'AS210644' => 'scanning',
    'AS210654' => 'scanning',
    'AS210703' => 'scanning',
    'AS210705' => 'scanning',
    'AS210707' => 'scanning',
    'AS210714' => 'scanning',
    'AS210756' => 'scanning',
    'AS210848' => 'scanning',
    'AS210950' => 'scanning',
    'AS211066' => 'scanning',
    'AS211121' => 'scanning',
    'AS211138' => 'scanning',
    'AS211199' => 'scanning',
    'AS211238' => 'scanning',
    'AS211507' => 'scanning',
    'AS211619' => 'scanning',
    'AS211659' => 'scanning',
    'AS211663' => 'scanning',
    'AS211720' => 'scanning',
    'AS211736' => 'scanning',
    'AS211762' => 'scanning',
    'AS211849' => 'scanning',
    'AS211922' => 'scanning',
    'AS211955' => 'scanning',
    'AS212017' => 'scanning',
    'AS212283' => 'scanning',
    'AS212448' => 'scanning',
    'AS212622' => 'scanning',
    'AS212651' => 'scanning',
    'AS212666' => 'scanning',
    'AS212867' => 'scanning',
    'AS213035' => 'scanning',
    'AS213137' => 'scanning',
    'AS213200' => 'scanning',
    'AS213355' => 'scanning',
    'AS213373' => 'scanning',
    'AS213389' => 'scanning',
    'AS213438' => 'scanning',
    'AS213441' => 'scanning',
    'AS213448' => 'scanning',
    'AS213474' => 'scanning',
    'AS213511' => 'scanning',
    'AS213652' => 'scanning',
    'AS213702' => 'scanning',
    'AS213725' => 'scanning',
    'AS213753' => 'scanning',
    'AS213790' => 'scanning',
    'AS213897' => 'scanning',
    'AS213921' => 'scanning',
    'AS213995' => 'scanning',
    'AS213999' => 'scanning',
    'AS214018' => 'scanning',
    'AS214295' => 'scanning',
    'AS214351' => 'scanning',
    'AS214357' => 'scanning',
    'AS214422' => 'scanning',
    'AS214472' => 'scanning',
    'AS214497' => 'scanning',
    'AS214717' => 'scanning',
    'AS214927' => 'scanning',
    'AS214940' => 'scanning',
    'AS215117' => 'scanning',
    'AS215127' => 'scanning',
    'AS215136' => 'scanning',
    'AS215183' => 'scanning',
    'AS215310' => 'scanning',
    'AS215311' => 'scanning',
    'AS215340' => 'scanning',
    'AS215376' => 'scanning',
    'AS215381' => 'scanning',
    'AS215460' => 'scanning',
    'AS215462' => 'scanning',
    'AS215474' => 'scanning',
    'AS215730' => 'scanning',
    'AS215765' => 'scanning',
    'AS215828' => 'scanning',
    'AS215925' => 'scanning',
    'AS215930' => 'scanning',
    'AS216127' => 'scanning',
    'AS216246' => 'scanning',
    'AS216341' => 'scanning',
    'AS266702' => 'scanning',
    'AS266724' => 'scanning',
    'AS327837' => 'scanning',
    'AS327952' => 'scanning',
    'AS328095' => 'scanning',
    'AS328819' => 'scanning',
    'AS328958' => 'scanning',
    'AS329007' => 'scanning',
    'AS329325' => 'scanning',
    'AS398638' => 'scanning',
    'AS398741' => 'scanning',
    'AS399073' => 'scanning',
    'AS399471' => 'scanning',
    'AS399979' => 'scanning',
    'AS400018' => 'scanning',
    'AS400171' => 'scanning',
    'AS400328' => 'scanning',
    'AS400377' => 'scanning',
    'AS400506' => 'scanning',
    'AS400992' => 'scanning',
    'AS401109' => 'scanning',
    'AS401110' => 'scanning',
    'AS401116' => 'scanning',
    'AS401120' => 'scanning',
    'AS401616' => 'scanning',
    'AS401626' => 'scanning',
    'AS401696' => 'scanning',
    'AS401701' => 'scanning',
    'AS402075' => 'scanning',
    'AS402253' => 'scanning',
    // --- END AUTO-SYNC SPAMHAUS ASN-DROP ---
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
