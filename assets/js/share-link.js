/**
 * Phase 2 share links (design doc D8): `#v=<compressed payload>` encoding
 * the CURRENT FILTERED rows' IPs plus the active filters. Pure encode/decode
 * + cap logic only — no DOM, no history.replaceState (that's R3's job in
 * workbench.js, which must run before the Umami tracker script loads).
 *
 * Compression: IPv4 addresses pack to 4 bytes and IPv6 to 16, instead of
 * ~7-15 ASCII bytes each as JSON strings. That's what gets a filtered view
 * under the ~8 KB URL cap at something close to the design doc's own
 * estimate ("roughly 1,000-1,500 IPv4 addresses after compression") without
 * pulling in a general-purpose compression library or depending on
 * CompressionStream, which isn't available in every target browser or in
 * the Jest/jsdom test environment used here.
 *
 * Wire format (before base64url):
 *   [1 byte version]
 *   [4 bytes uint32 BE: ip count]
 *   for each ip: [1 byte type: 4 or 6][4 or 16 bytes, network order]
 *   [remaining bytes: UTF-8 JSON { c: [categories], k: [countries], s: search }]
 *
 * UMD: exposes `window.ip2geoShareLink`, and `module.exports` for Jest.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ip2geoShareLink = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = 1;
  // ~8 KB URL cap (design doc D8). Measured against the encoded fragment
  // text length (base64url chars), not the raw binary — that's what
  // actually goes in the address bar.
  var URL_CAP_CHARS = 8 * 1024;

  // ── base64url, works in both a browser and Node/Jest ────────────────────

  function bytesToBase64Url(bytes) {
    var b64;
    if (typeof Buffer !== 'undefined') {
      b64 = Buffer.from(bytes).toString('base64');
    } else {
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      b64 = btoa(bin);
    }
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64UrlToBytes(str) {
    var b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(b64, 'base64'));
    }
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function utf8Encode(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    return new Uint8Array(Buffer.from(str, 'utf8'));
  }

  function utf8Decode(bytes) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(bytes);
    return Buffer.from(bytes).toString('utf8');
  }

  // ── IP <-> bytes ──────────────────────────────────────────────────────

  function packIPv4(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return null;
    var out = new Uint8Array(4);
    for (var i = 0; i < 4; i++) {
      var n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      out[i] = n;
    }
    return out;
  }

  function unpackIPv4(bytes) {
    return bytes[0] + '.' + bytes[1] + '.' + bytes[2] + '.' + bytes[3];
  }

  /** Expects a normalized (no ::  shorthand required) or shorthand IPv6 address; expands to 8 groups. */
  function packIPv6(ip) {
    var out = new Uint8Array(16);
    var halves = ip.split('::');
    var head = halves[0] ? halves[0].split(':') : [];
    var tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    if (halves.length > 2) return null;
    var missing = 8 - (head.length + tail.length);
    if (halves.length === 1 && missing !== 0) return null; // no :: means exactly 8 groups required
    if (halves.length === 2 && missing < 0) return null;
    var groups = head.concat(new Array(Math.max(missing, 0)).fill('0')).concat(tail);
    if (groups.length !== 8) return null;
    for (var i = 0; i < 8; i++) {
      var g = groups[i] === '' ? 0 : parseInt(groups[i], 16);
      if (Number.isNaN(g) || g < 0 || g > 0xffff) return null;
      out[i * 2] = (g >> 8) & 0xff;
      out[i * 2 + 1] = g & 0xff;
    }
    return out;
  }

  function unpackIPv6(bytes) {
    var groups = [];
    for (var i = 0; i < 8; i++) {
      groups.push(((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16));
    }
    // Collapse the longest run of zero groups into "::" (standard IPv6 shorthand).
    var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (var g = 0; g < 8; g++) {
      if (groups[g] === '0') {
        if (curStart === -1) curStart = g;
        curLen++;
        if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
      } else {
        curStart = -1; curLen = 0;
      }
    }
    if (bestLen > 1) {
      var left = groups.slice(0, bestStart);
      var right = groups.slice(bestStart + bestLen);
      return left.join(':') + '::' + right.join(':');
    }
    return groups.join(':');
  }

  function packIp(ip) {
    if (ip.indexOf(':') !== -1) {
      var v6 = packIPv6(ip);
      return v6 ? { type: 6, bytes: v6 } : null;
    }
    var v4 = packIPv4(ip);
    return v4 ? { type: 4, bytes: v4 } : null;
  }

  // ── payload encode/decode ────────────────────────────────────────────

  /**
   * @param {{ips: string[], categories: string[], countries: string[], search: string}} state
   * @returns {?string} the base64url fragment payload (without the leading
   *   "#v="), or null if any IP couldn't be packed (malformed input).
   */
  function encodeShareState(state) {
    var ips = state.ips || [];
    var packed = [];
    var total = 0;
    for (var i = 0; i < ips.length; i++) {
      var p = packIp(ips[i]);
      if (!p) return null;
      packed.push(p);
      total += 1 + p.bytes.length;
    }

    var filtersJson = utf8Encode(JSON.stringify({
      c: state.categories || [],
      k: state.countries || [],
      s: state.search || ''
    }));

    var buf = new Uint8Array(1 + 4 + total + filtersJson.length);
    var offset = 0;
    buf[offset++] = VERSION;
    buf[offset++] = (ips.length >>> 24) & 0xff;
    buf[offset++] = (ips.length >>> 16) & 0xff;
    buf[offset++] = (ips.length >>> 8) & 0xff;
    buf[offset++] = ips.length & 0xff;
    packed.forEach(function (p) {
      buf[offset++] = p.type;
      buf.set(p.bytes, offset);
      offset += p.bytes.length;
    });
    buf.set(filtersJson, offset);

    return bytesToBase64Url(buf);
  }

  /**
   * @param {string} payload the base64url string (without "#v=")
   * @returns {?{ips: string[], categories: string[], countries: string[], search: string}}
   *   null if the payload is malformed/unparseable.
   */
  function decodeShareState(payload) {
    try {
      var buf = base64UrlToBytes(payload);
      var offset = 0;
      var version = buf[offset++];
      if (version !== VERSION) return null;
      var count = (buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3];
      offset += 4;

      var ips = [];
      for (var i = 0; i < count; i++) {
        var type = buf[offset++];
        if (type === 4) {
          ips.push(unpackIPv4(buf.subarray(offset, offset + 4)));
          offset += 4;
        } else if (type === 6) {
          ips.push(unpackIPv6(buf.subarray(offset, offset + 16)));
          offset += 16;
        } else {
          return null;
        }
      }

      var filters = JSON.parse(utf8Decode(buf.subarray(offset)));
      return {
        ips: ips,
        categories: filters.c || [],
        countries: filters.k || [],
        search: filters.s || ''
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * @returns {{payload: ?string, chars: number, overCap: boolean, cap: number}}
   *   payload is null when encoding failed outright (bad IPs); overCap is
   *   true when it encoded fine but is too big for the URL.
   */
  function buildShareLink(state) {
    var payload = encodeShareState(state);
    if (payload === null) {
      return { payload: null, chars: 0, overCap: true, cap: URL_CAP_CHARS };
    }
    return { payload: payload, chars: payload.length, overCap: payload.length > URL_CAP_CHARS, cap: URL_CAP_CHARS };
  }

  /** D8 over-cap label: "Too many IPs for a link (3,412 / ~1,200)". ~cap is estimated in IPv4-equivalent count from URL_CAP_CHARS. */
  function overCapLabel(ipCount) {
    // 1 version byte + 4 count bytes + per-ip (1 type + 4 bytes) ~ 5 bytes/ip for IPv4-heavy sets,
    // base64 inflates by 4/3 => chars ~= bytes * 4/3. Solve for ip count at the char cap.
    var approxCapIps = Math.floor(((URL_CAP_CHARS * 3) / 4 - 5) / 5);
    return 'Too many IPs for a link (' + ipCount.toLocaleString() + ' / ~' + approxCapIps.toLocaleString() + ')';
  }

  /** D8: the .ip2geo.json view-file fallback when a link would be over cap. */
  function buildViewFile(state) {
    return JSON.stringify({
      version: VERSION,
      ips: state.ips || [],
      categories: state.categories || [],
      countries: state.countries || [],
      search: state.search || ''
    }, null, 2);
  }

  return {
    VERSION: VERSION,
    URL_CAP_CHARS: URL_CAP_CHARS,
    encodeShareState: encodeShareState,
    decodeShareState: decodeShareState,
    buildShareLink: buildShareLink,
    overCapLabel: overCapLabel,
    buildViewFile: buildViewFile,
    _internal: { packIPv4: packIPv4, unpackIPv4: unpackIPv4, packIPv6: packIPv6, unpackIPv6: unpackIPv6 }
  };
});
