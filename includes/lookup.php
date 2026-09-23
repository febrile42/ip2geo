<?php
/**
 * Shared GeoIP + ASN lookup, backed by MaxMind's official .mmdb reader.
 *
 * Used by both the HTML page (index.php, per R4) and the JSON endpoint
 * (api/lookup.php). One reader per database is opened per call and reused
 * for every IP in the batch — opening a reader per IP would reintroduce the
 * per-IP overhead this replaces (design doc, R4/P2).
 *
 *   lookup_ips(['1.2.3.4', '2001:db8::1'])
 *     │
 *     ├─ resolve DB paths (args, else GEOIP_MMDB_DIR/GeoLite2-{City,ASN}.mmdb)
 *     │
 *     ├─ open ONE MaxMind\Db\Reader for GeoLite2-City.mmdb  ──┐
 *     ├─ open ONE MaxMind\Db\Reader for GeoLite2-ASN.mmdb   ──┤  reused below
 *     │     (missing file or corrupt db → GeoDbUnavailableException)
 *     │                                                       │
 *     └─ foreach $ip (v4 or v6, one Reader::get() per db per IP):
 *           city reader  ──▶ country_iso_code, country_name,
 *                            subdivision_1_name, city_name
 *           asn  reader  ──▶ autonomous_system_number, autonomous_system_org
 *           no match ──▶ the field is null, not an error
 *
 *  Returns: [ ip => ['country_iso_code' => ?string, 'country_name' => ?string,
 *                     'subdivision_1_name' => ?string, 'city_name' => ?string,
 *                     'autonomous_system_number' => ?int,
 *                     'autonomous_system_org' => ?string], ... ]
 *
 * Field meaning mirrors the MySQL loop it replaces (index.php:290-305,
 * geoip2_network_current_int / geoip2_asn_current_int).
 */

declare(strict_types=1);

use MaxMind\Db\Reader;
use MaxMind\Db\Reader\InvalidDatabaseException;

// Where the monthly job (scripts/update-geoip.sh) drops GeoLite2-City.mmdb
// and GeoLite2-ASN.mmdb. Override in config.php: define('GEOIP_MMDB_DIR', '...');
// before this file is required. Documented in config.sample.php.
if (!defined('GEOIP_MMDB_DIR')) {
    define('GEOIP_MMDB_DIR', dirname(__DIR__) . '/data/geoip');
}

/**
 * Thrown when a .mmdb file is missing or fails to parse (corrupt / mid-swap).
 * api/lookup.php maps this to a 503 so a bad or in-flight monthly update
 * shows a clear message instead of a blank page or a fatal error.
 */
class GeoDbUnavailableException extends \RuntimeException
{
}

/**
 * Open a MaxMind\Db\Reader, translating file/parse failures into
 * GeoDbUnavailableException. Every open is counted in a module-level
 * counter so tests can assert the reader is opened once per database per
 * call, not once per IP (lookup_reader_open_count() / reset below).
 */
function _lookup_open_mmdb_reader(string $path): Reader
{
    global $__lookup_reader_open_count;
    $__lookup_reader_open_count = ($__lookup_reader_open_count ?? 0) + 1;

    if (!is_file($path) || !is_readable($path)) {
        throw new GeoDbUnavailableException("GeoIP database not found or unreadable: {$path}");
    }

    try {
        return new Reader($path);
    } catch (\InvalidArgumentException | \UnexpectedValueException | InvalidDatabaseException $e) {
        // InvalidArgumentException: file vanished between is_file() and open (e.g. an
        // atomic swap mid-request). UnexpectedValueException / InvalidDatabaseException:
        // file exists but isn't a valid .mmdb (corrupt / truncated download).
        throw new GeoDbUnavailableException(
            "GeoIP database at {$path} could not be opened: " . $e->getMessage(),
            0,
            $e
        );
    }
}

/** Test-only seam: how many times a reader was opened since the last reset. */
function lookup_reader_open_count(): int
{
    global $__lookup_reader_open_count;
    return $__lookup_reader_open_count ?? 0;
}

/** Test-only seam: zero the reader-open counter. */
function reset_lookup_reader_open_count(): void
{
    global $__lookup_reader_open_count;
    $__lookup_reader_open_count = 0;
}

/**
 * Look up a batch of IPv4/IPv6 addresses against the GeoLite2 City + ASN
 * .mmdb databases, opening each reader once and reusing it for every IP.
 *
 * @param string[]    $ips     IP address strings (v4 or v6). Not validated
 *                             here — pass only strings you already know are
 *                             syntactically valid IPs; garbage in, null
 *                             fields out (Reader::get() would throw on a
 *                             genuinely malformed argument, which callers
 *                             should filter before reaching this function).
 * @param string|null $cityDb  Path to GeoLite2-City.mmdb. Defaults to
 *                             GEOIP_MMDB_DIR . '/GeoLite2-City.mmdb'.
 * @param string|null $asnDb   Path to GeoLite2-ASN.mmdb. Defaults to
 *                             GEOIP_MMDB_DIR . '/GeoLite2-ASN.mmdb'.
 *
 * @return array<string, array{country_iso_code: ?string, country_name: ?string,
 *                              subdivision_1_name: ?string, city_name: ?string,
 *                              autonomous_system_number: ?int,
 *                              autonomous_system_org: ?string}>
 *
 * @throws GeoDbUnavailableException if either database is missing or corrupt.
 */
function lookup_ips(array $ips, ?string $cityDb = null, ?string $asnDb = null): array
{
    $cityPath = $cityDb ?? GEOIP_MMDB_DIR . '/GeoLite2-City.mmdb';
    $asnPath  = $asnDb ?? GEOIP_MMDB_DIR . '/GeoLite2-ASN.mmdb';

    // Open once; reused for every IP below (design doc R4/P2).
    $cityReader = _lookup_open_mmdb_reader($cityPath);
    $asnReader  = _lookup_open_mmdb_reader($asnPath);

    $results = [];

    try {
        foreach ($ips as $ip) {
            $cityRecord = null;
            $asnRecord  = null;

            try {
                $cityRecord = $cityReader->get($ip);
            } catch (\InvalidArgumentException $e) {
                // Not a syntactically valid IP for the reader; treat as no match
                // rather than aborting the whole batch over one bad entry.
                $cityRecord = null;
            }

            try {
                $asnRecord = $asnReader->get($ip);
            } catch (\InvalidArgumentException $e) {
                $asnRecord = null;
            }

            $country      = $cityRecord['country'] ?? null;
            $subdivisions = $cityRecord['subdivisions'] ?? null;
            $city         = $cityRecord['city'] ?? null;

            $results[$ip] = [
                'country_iso_code'   => $country['iso_code'] ?? null,
                'country_name'       => $country['names']['en'] ?? null,
                'subdivision_1_name' => $subdivisions[0]['names']['en'] ?? null,
                'city_name'          => $city['names']['en'] ?? null,
                'autonomous_system_number' => isset($asnRecord['autonomous_system_number'])
                    ? (int)$asnRecord['autonomous_system_number']
                    : null,
                'autonomous_system_org' => $asnRecord['autonomous_system_organization'] ?? null,
            ];
        }
    } finally {
        $cityReader->close();
        $asnReader->close();
    }

    return $results;
}
