<?php
/**
 * Client IP for rate limiting, shared by api/lookup.php and index.php's
 * no-JS POST path (IPG-17), so both entry points key their limiter the same
 * way.
 *
 * Not the same as index.php's getRealIPAddr(): that one only labels the
 * visitor's own "(you)" sample row and deliberately trusts any header (R16).
 * This one is a security boundary and only trusts CF-Connecting-IP from a
 * Cloudflare edge (IPG-10 F2).
 */

declare(strict_types=1);

// Cloudflare's published edge ranges (https://www.cloudflare.com/ips/,
// fetched 2026-09-26). CF-Connecting-IP is only trusted when the request
// actually came from one of these; anything else hit the origin directly and
// could put any value in that header. Cloudflare changes this list rarely;
// re-check it when touching this file.
if (!defined('CLOUDFLARE_IP_RANGES')) {
    define('CLOUDFLARE_IP_RANGES', [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ]);
}

/** True if $ip (v4 or v6) is inside $cidr. Mismatched families never match. */
function lookup_endpoint_ip_in_cidr(string $ip, string $cidr): bool
{
    [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
    $ipBin  = @inet_pton($ip);
    $netBin = @inet_pton((string)$net);
    if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
        return false;
    }
    $maxBits = strlen($ipBin) * 8;
    $bits    = $bits === null ? $maxBits : (int)$bits;
    if ($bits < 0 || $bits > $maxBits) {
        return false;
    }
    $bytes = intdiv($bits, 8);
    if (substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
}

function lookup_endpoint_is_cloudflare(string $ip): bool
{
    foreach (CLOUDFLARE_IP_RANGES as $cidr) {
        if (lookup_endpoint_ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * Client IP for rate limiting. CF-Connecting-IP only when REMOTE_ADDR is a
 * Cloudflare edge and the header holds a valid IP; otherwise REMOTE_ADDR,
 * so a direct-to-origin caller can't mint a fresh rate-limit bucket per
 * request by varying the header.
 */
function lookup_endpoint_client_ip(array $server): string
{
    $remote = trim((string)($server['REMOTE_ADDR'] ?? ''));
    $cf     = trim((string)($server['HTTP_CF_CONNECTING_IP'] ?? ''));
    if ($cf !== '' && lookup_endpoint_is_cloudflare($remote) && filter_var($cf, FILTER_VALIDATE_IP) !== false) {
        return $cf;
    }
    return $remote;
}
