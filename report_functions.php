<?php
/**
 * Shared pure functions used by index.php's lookup path and the test suite.
 *
 * Threat Reports were retired in v5.0.0 (R17): the report-generation, free
 * teaser, and AbuseIPDB-enrichment functions that used to live here are gone.
 * What's left is the Spamhaus DROP reputation axis, which the lookup page
 * and the JSON API both use directly (ip2geo_ip_in_spamhaus_drop()).
 *
 * Keeping these here (not embedded inline) makes them unit-testable
 * without booting the full page or a DB connection.
 */

// Kill switch for the Spamhaus DROP reputation axis (the residential-attacker CTA
// override on the lookup page). Flip to false to disable all of it instantly
// without a code change to the hot loop — handy if the override ever misfires
// in prod. Defined here (loaded by index.php) so the gate is in scope there.
if (!defined('REPUTATION_AXIS_ENABLED')) {
    define('REPUTATION_AXIS_ENABLED', true);
}

// Spamhaus DROP reputation data, machine-generated weekly by
// .github/workflows/sync-spamhaus-drop.yml (that file is never hand-edited).
// $spamhaus_drop_ranges — sorted, non-overlapping [start_int, end_int] pairs;
// the O(log n) membership hot path used by ip_in_spamhaus_drop() below.
// spamhaus_drop_data.php also defines $spamhaus_drop_cidrs (the un-merged,
// per-netblock originals); nothing here consumes it since Threat Reports
// (the only caller that named the specific covering CIDR) were retired in
// v5.0.0 — kept in the data file for the generator/tests, unused at runtime.
require_once __DIR__ . '/spamhaus_drop_data.php';

/**
 * Is an IPv4 address (as an unsigned 32-bit int) inside any Spamhaus DROP range?
 *
 * DROP lists netblocks controlled by criminals/hijackers, so a hit is a high-
 * confidence "this IP is bad" signal independent of ASN classification. Used by
 * the lookup hot loop to fire the threat CTA on residential attackers that the
 * ASN-based verdict would otherwise miss.
 *
 * Binary search over the sorted, disjoint $spamhaus_drop_ranges → O(log n).
 *
 * @param int $ip_int  Unsigned 32-bit IPv4 as int. IPv6/invalid IPs should
 *                     never reach here — use ip2geo_ip_in_spamhaus_drop()
 *                     for a full IP string, which handles that.
 * @return bool
 */
function ip_in_spamhaus_drop(int $ip_int): bool {
    global $spamhaus_drop_ranges;
    $lo = 0;
    $hi = count($spamhaus_drop_ranges) - 1;
    while ($lo <= $hi) {
        $mid = intdiv($lo + $hi, 2);
        if ($ip_int < $spamhaus_drop_ranges[$mid][0]) {
            $hi = $mid - 1;
        } elseif ($ip_int > $spamhaus_drop_ranges[$mid][1]) {
            $lo = $mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

/**
 * Spamhaus DROP flag for one resolved IP — shared by index.php's HTML page
 * and api/lookup.php's JSON endpoint so both stay in lockstep. DROP is an
 * IPv4-only netblock list, so IPv6 (and any unparseable input) always
 * returns false, same as REPUTATION_AXIS_ENABLED being off.
 *
 * Replaces the formerly-duplicated ipToLong() (index.php) and
 * lookup_endpoint_ip4_to_uint() (api/lookup.php), which existed only to feed
 * ip_in_spamhaus_drop() an unsigned 32-bit int.
 */
function ip2geo_ip_in_spamhaus_drop(string $ip): bool
{
    if (!REPUTATION_AXIS_ENABLED) {
        return false;
    }
    $long = ip2long($ip);
    if ($long === false) {
        return false;
    }
    return ip_in_spamhaus_drop((int) sprintf('%u', $long));
}
