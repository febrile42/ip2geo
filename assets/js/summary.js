/**
 * JS port of includes/summary.php's build_summary() (design doc: "Summary
 * line uses the same rules as includes/summary.php; port build_summary to
 * JS and prove parity with a fixture" — see tests/js/summary.test.js, which
 * shells out to the real PHP function on the same fixture rows).
 *
 * Kept in lockstep with includes/summary.php by hand — same category
 * vocabulary and order, same zero-omission rule, same top-3-ASN rule, same
 * line assembly. If one changes, the other and the parity test must too.
 *
 * UMD: exposes `window.ip2geoSummary`, and `module.exports` for Jest.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ip2geoSummary = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Mirrors SUMMARY_CATEGORY_LABELS in includes/summary.php — order matters
  // (it's the tie-break vocabulary order for equal-count categories).
  var SUMMARY_CATEGORY_LABELS = {
    scanning: 'Scanning',
    cloud: 'Cloud exit',
    vpn: 'VPN/Proxy',
    residential: 'Residential',
    unknown: 'Unknown'
  };
  var VOCAB_ORDER = Object.keys(SUMMARY_CATEGORY_LABELS);

  function numberFormat(n) {
    return n.toLocaleString('en-US');
  }

  /**
   * @param {Array<{category: string, asn?: string, asn_org?: string, drop?: boolean}>} rows
   * @returns {{total:number, categories:Array, top_asns:Array, drop_count:number, top_asn:?object, line:string}}
   */
  function buildSummary(rows) {
    var total = rows.length;

    if (total === 0) {
      return { total: 0, categories: [], top_asns: [], drop_count: 0, top_asn: null, line: '' };
    }

    var counts = {};
    VOCAB_ORDER.forEach(function (k) { counts[k] = 0; });
    var dropCount = 0;
    var asnCounts = {}; // 'AS14061' -> { org, count }

    rows.forEach(function (row) {
      var cat = row.category || 'unknown';
      if (!(cat in counts)) cat = 'unknown';
      counts[cat]++;

      if (row.drop) dropCount++;

      var asn = row.asn || '';
      if (asn !== '') {
        if (!asnCounts[asn]) asnCounts[asn] = { org: row.asn_org || '', count: 0 };
        asnCounts[asn].count++;
      }
    });

    var categories = [];
    VOCAB_ORDER.forEach(function (key) {
      var count = counts[key];
      if (count === 0) return;
      categories.push({
        key: key,
        label: SUMMARY_CATEGORY_LABELS[key],
        count: count,
        pct: Math.round((count / total) * 100)
      });
    });
    categories.sort(function (a, b) {
      if (a.count !== b.count) return b.count - a.count;
      return VOCAB_ORDER.indexOf(a.key) - VOCAB_ORDER.indexOf(b.key);
    });

    var topAsns = Object.keys(asnCounts).map(function (asn) {
      return { asn: asn, org: asnCounts[asn].org, count: asnCounts[asn].count };
    });
    // Stable sort by count desc (Array#sort is stable in all supported
    // engines here, matching PHP's usort with a strict comparator).
    topAsns.sort(function (a, b) { return b.count - a.count; });
    topAsns = topAsns.slice(0, 3);

    // Single leading ASN (IPG-33): only claim a "Top ASN" when the leader
    // actually leads — at least 2 IPs, and strictly more than the runner-up.
    // A 1-IP "top" or a tie between the top two is not a finding.
    var topAsn = null;
    if (topAsns.length > 0 && topAsns[0].count >= 2
        && (topAsns.length === 1 || topAsns[0].count > topAsns[1].count)) {
      topAsn = topAsns[0];
    }

    var parts = [];
    if (dropCount === 1) {
      parts.push('1 IP in a Spamhaus DROP netblock');
    } else if (dropCount > 1) {
      parts.push(numberFormat(dropCount) + ' IPs in Spamhaus DROP netblocks');
    }
    if (topAsn !== null) {
      var asnText = (topAsn.asn + ' ' + topAsn.org).trim();
      parts.push('Top ASN: ' + asnText + ' (' + numberFormat(topAsn.count) + ' IPs)');
    }

    return {
      total: total,
      categories: categories,
      top_asns: topAsns,
      drop_count: dropCount,
      top_asn: topAsn,
      line: parts.join(' · ')
    };
  }

  return { buildSummary: buildSummary, SUMMARY_CATEGORY_LABELS: SUMMARY_CATEGORY_LABELS };
});
