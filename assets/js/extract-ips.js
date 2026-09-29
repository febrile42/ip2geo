/**
 * Browser mirror of includes/extract.php's extract_ips(). Same semantics,
 * same golden fixtures (tests/fixtures/extract/), locked together by
 * tests/js/extract-ips.test.js and tests/ExtractIpsTest.php.
 *
 * IPv4 extraction, occurrence counting, the 10,000-unique cap (applied
 * before the private filter, combined across v4+v6) and IPv4 private-range
 * filtering are byte-for-byte the same rules as the PHP side — see the
 * header comment in includes/extract.php for the two intentional quirks
 * carried over from the original inline index.php extraction.
 *
 * IPv6 uses a two-step scan (design doc R15): a single linear pass finds
 * candidate runs of [0-9A-Fa-f:.], then each candidate is strictly
 * validated and normalized. No single large IPv6 regex is used anywhere in
 * this file, specifically to avoid catastrophic backtracking on long
 * hex/colon runs (MAC addresses, hashes, "::::" noise) that show up in
 * real pasted logs — see tests/js/extract-ips.test.js's worst-case-2mb
 * generator and its <300ms assertion.
 *
 * UMD: exposes `window.extractIps` in the browser, and `module.exports` for
 * Jest's `require()`.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.extractIps = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var EXTRACT_IPS_CAP = 10000;

  var IPV4_RE = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  var V6_CANDIDATE_RE = /[0-9A-Fa-f:.]+/g;
  var HEX_GROUP_RE = /^[0-9A-Fa-f]{1,4}$/;
  var PRIVATE_V4_RE = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|::1$)/;

  // ── IPv4 helpers ───────────────────────────────────────────────────────────

  function isPrivateV4(ip) {
    return PRIVATE_V4_RE.test(ip);
  }

  function parseIPv4Octets(v4) {
    var parts = v4.split('.');
    if (parts.length !== 4) return null;
    var out = [];
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return null;
      var n = parseInt(parts[i], 10);
      if (n < 0 || n > 255) return null;
      out.push(n);
    }
    return out;
  }

  // ── IPv6 parsing ─────────────────────────────────────────────────────────

  /** Parse a candidate string into 8 uint16 groups, or null if invalid. */
  function parseIPv6Groups(ip) {
    if (typeof ip !== 'string' || ip.length === 0) return null;

    var firstDc = ip.indexOf('::');
    var lastDc = ip.lastIndexOf('::');
    if (firstDc !== lastDc) return null; // more than one "::"

    var hasDoubleColon = firstDc !== -1;
    var head = hasDoubleColon ? ip.slice(0, firstDc) : ip;
    var tail = hasDoubleColon ? ip.slice(firstDc + 2) : '';

    var headParts = head === '' ? [] : head.split(':');
    var tailParts = tail === '' ? [] : tail.split(':');

    // An embedded dotted IPv4 tail is only legal as the last group of
    // whichever side is "last" (tail if "::" is present, else head).
    var lastArr = hasDoubleColon ? tailParts : headParts;
    if (lastArr.length > 0 && lastArr[lastArr.length - 1].indexOf('.') !== -1) {
      var v4 = lastArr[lastArr.length - 1];
      var octets = parseIPv4Octets(v4);
      if (!octets) return null;
      var hi = ((octets[0] << 8) | octets[1]) & 0xffff;
      var lo = ((octets[2] << 8) | octets[3]) & 0xffff;
      lastArr[lastArr.length - 1] = hi.toString(16);
      lastArr.push(lo.toString(16));
    }

    if (headParts.some(function (g) { return g === '' || !HEX_GROUP_RE.test(g); })) return null;
    if (tailParts.some(function (g) { return g === '' || !HEX_GROUP_RE.test(g); })) return null;

    var totalGroups = headParts.length + tailParts.length;
    if (hasDoubleColon) {
      if (totalGroups > 7) return null; // "::" must stand in for >=1 group
    } else {
      if (totalGroups !== 8) return null;
    }

    var groups = [];
    for (var i = 0; i < headParts.length; i++) groups.push(parseInt(headParts[i], 16));
    var zeros = 8 - totalGroups;
    for (var z = 0; z < zeros; z++) groups.push(0);
    for (var j = 0; j < tailParts.length; j++) groups.push(parseInt(tailParts[j], 16));

    if (groups.length !== 8) return null;
    return groups;
  }

  /**
   * Canonical lowercase-compressed form matching this platform's PHP
   * inet_ntop() (glibc): standard RFC 5952 zero-run compression, PLUS two
   * embedded-IPv4 dotted-quad special cases empirically confirmed against
   * PHP on this box:
   *   - the longest zero run is exactly groups[0..5] (length 6) → the
   *     trailing two groups print as a dotted quad ("::a.b.c.d")
   *   - the longest zero run is exactly groups[0..4] (length 5) and
   *     groups[5] === 0xffff → the IPv4-mapped form ("::ffff:a.b.c.d")
   * Any other zero run (including length 7, i.e. "::N" with a single
   * trailing group) prints in ordinary hex — confirmed against PHP, which
   * does NOT dotted-quad that case despite some inet_ntop implementations
   * doing so.
   */
  function groupsToCanonical(groups) {
    var bestStart = -1, bestLen = 0;
    var curStart = -1, curLen = 0;
    for (var i = 0; i < 8; i++) {
      if (groups[i] === 0) {
        if (curStart === -1) curStart = i;
        curLen++;
        if (curLen > bestLen) {
          bestLen = curLen;
          bestStart = curStart;
        }
      } else {
        curStart = -1;
        curLen = 0;
      }
    }

    if (bestStart === 0 && bestLen === 6) {
      return '::' + groupsToV4Dotted(groups[6], groups[7]);
    }
    if (bestStart === 0 && bestLen === 5 && groups[5] === 0xffff) {
      return '::ffff:' + groupsToV4Dotted(groups[6], groups[7]);
    }

    var hex = groups.map(function (g) { return g.toString(16); });

    if (bestLen < 2) {
      return hex.join(':');
    }

    var before = hex.slice(0, bestStart);
    var after = hex.slice(bestStart + bestLen);
    var left = before.join(':');
    var right = after.join(':');

    if (before.length === 0 && after.length === 0) return '::';
    if (before.length === 0) return '::' + right;
    if (after.length === 0) return left + '::';
    return left + '::' + right;
  }

  function groupsToV4Dotted(hiGroup, loGroup) {
    return [(hiGroup >> 8) & 0xff, hiGroup & 0xff, (loGroup >> 8) & 0xff, loGroup & 0xff].join('.');
  }

  function normalizeV6(ip) {
    var groups = parseIPv6Groups(ip);
    if (!groups) return null;
    return groupsToCanonical(groups);
  }

  function validateV6Candidate(token) {
    var groups = parseIPv6Groups(token);
    if (!groups) return null;
    return groupsToCanonical(groups);
  }

  /** Private/local per the design doc: ::1, fc00::/7, fe80::/10, mapped-private v4, 2001:db8::/32. */
  function isPrivateV6FromGroups(groups) {
    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
        groups[4] === 0 && groups[5] === 0 && groups[6] === 0 && groups[7] === 1) {
      return true; // ::1
    }

    var byte0 = groups[0] >> 8;
    var byte1 = groups[0] & 0xff;

    if ((byte0 & 0xfe) === 0xfc) return true; // fc00::/7
    if (byte0 === 0xfe && (byte1 & 0xc0) === 0x80) return true; // fe80::/10
    if (groups[0] === 0x2001 && groups[1] === 0x0db8) return true; // 2001:db8::/32

    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
        groups[4] === 0 && groups[5] === 0xffff) {
      var a = groups[6] >> 8, b = groups[6] & 0xff, c = groups[7] >> 8, d = groups[7] & 0xff;
      return isPrivateV4(a + '.' + b + '.' + c + '.' + d);
    }

    return false;
  }

  function isPrivateV6(ip) {
    var groups = parseIPv6Groups(ip);
    if (!groups) return false;
    return isPrivateV6FromGroups(groups);
  }

  // ── extractIps ──────────────────────────────────────────────────────────

  /**
   * extractIps(text) -> { ips: [[ip, count], ...], totalUnique, v6Count }
   *
   * ips is ordered like PHP's associative-array insertion order: first-seen
   * order across v4+v6 as they appear in the text, capped at
   * EXTRACT_IPS_CAP unique keys (combined v4+v6, cap before the private
   * filter), then with private/local addresses dropped.
   */
  function extractIps(text) {
    var hits = []; // [offset, type, ip]

    var m;
    IPV4_RE.lastIndex = 0;
    while ((m = IPV4_RE.exec(text)) !== null) {
      hits.push([m.index, 'v4', m[0]]);
      if (m[0].length === 0) IPV4_RE.lastIndex++; // guard against zero-length loops
    }

    V6_CANDIDATE_RE.lastIndex = 0;
    while ((m = V6_CANDIDATE_RE.exec(text)) !== null) {
      var token = m[0];
      if (token.indexOf(':') !== -1) {
        var normalized = validateV6Candidate(token);
        if (normalized !== null) {
          hits.push([m.index, 'v6', normalized]);
        }
      }
      if (m[0].length === 0) V6_CANDIDATE_RE.lastIndex++;
    }

    hits.sort(function (a, b) { return a[0] - b[0]; });

    var rawFreq = Object.create(null);
    var rawType = Object.create(null);
    var order = [];
    for (var i = 0; i < hits.length; i++) {
      var ip = hits[i][2];
      var type = hits[i][1];
      if (!(ip in rawFreq)) {
        rawFreq[ip] = 0;
        rawType[ip] = type;
        order.push(ip);
      }
      rawFreq[ip]++;
    }

    var totalUnique = 0;
    for (var k = 0; k < order.length; k++) {
      var ipk = order[k];
      var isPriv = rawType[ipk] === 'v4' ? isPrivateV4(ipk) : isPrivateV6(ipk);
      if (!isPriv) totalUnique++;
    }

    var cappedOrder = order.slice(0, EXTRACT_IPS_CAP);

    var ips = [];
    var v6Count = 0;
    for (var c = 0; c < cappedOrder.length; c++) {
      var cip = cappedOrder[c];
      var ctype = rawType[cip];
      var priv = ctype === 'v4' ? isPrivateV4(cip) : isPrivateV6(cip);
      if (priv) continue;
      ips.push([cip, rawFreq[cip]]);
      if (ctype === 'v6') v6Count++;
    }

    return {
      ips: ips,
      totalUnique: totalUnique,
      v6Count: v6Count
    };
  }

  extractIps._internal = {
    isPrivateV4: isPrivateV4,
    isPrivateV6: isPrivateV6,
    normalizeV6: normalizeV6,
    parseIPv6Groups: parseIPv6Groups
  };

  return extractIps;
});
