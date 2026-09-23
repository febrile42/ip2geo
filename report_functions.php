<?php
/**
 * Shared pure functions used by index.php's lookup path and the test suite.
 *
 * Threat Reports were retired in v5.0.0 (R17): the report-generation, free
 * teaser, and AbuseIPDB-enrichment functions that used to live here are gone.
 * What's left is the Spamhaus DROP reputation axis, which the lookup page
 * still uses directly (ip_in_spamhaus_drop, apply_reputation_override).
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
 * @param int $ip_int  Unsigned 32-bit IPv4 as int. Pass (int) ipToLong($ip);
 *                     ipToLong() returns sprintf('%u', ip2long($ip)) as a string,
 *                     and IPv6/invalid IPs collapse to 0 (never listed in DROP).
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
 * Apply the Spamhaus DROP reputation override to a computed verdict + CTA state.
 *
 * A DROP hit is high-confidence criminal/hijacked space. Any hit (with the
 * existing >=5-IP floor) opens the CTA and floors the verdict at MODERATE, even
 * when the ASN-based verdict is LOW — this is what makes a residential fail2ban
 * paste fire. reputation_count == 0 returns the inputs unchanged (regression-safe).
 *
 * Pure: extracted from the index.php lookup path so it is unit-testable.
 * The REPUTATION_AXIS_ENABLED kill switch is checked by the caller.
 *
 * @param string $verdict_level   'HIGH' | 'MODERATE' | 'LOW'
 * @param bool   $show_cta        Whether the CTA would show pre-override
 * @param int    $matches_total   Non-good-country IP count (the >=5 floor)
 * @param int    $reputation_count Count of IPs on the Spamhaus DROP list
 * @param string $verdict_reason  Reason string computed pre-override ('' if none)
 * @return array{verdict_level:string, show_cta:bool, verdict_reason:string}
 */
function apply_reputation_override(
    string $verdict_level,
    bool $show_cta,
    int $matches_total,
    int $reputation_count,
    string $verdict_reason
): array {
    if ($matches_total >= 5 && $reputation_count >= 1) {
        $show_cta = true;
        if ($verdict_level === 'LOW') {
            $verdict_level = 'MODERATE';
        }
        if ($verdict_reason === '') {
            $verdict_reason = $reputation_count . ' IP' . ($reputation_count === 1 ? '' : 's')
                . ' on the Spamhaus DROP list (hijacked/criminal netblocks).';
        }
    }
    return [
        'verdict_level'  => $verdict_level,
        'show_cta'       => $show_cta,
        'verdict_reason' => $verdict_reason,
    ];
}
