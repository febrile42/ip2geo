/**
 * Phase 2 Export ▾ menu templates (design doc D9, revised — "one format at
 * every size", supersedes the plan's original "past 1,000 values -> CSV
 * lookup table" rule). Pure string-building only; assets/js/workbench.js
 * wires these into the menu, the toast and the "Copy" action.
 *
 * Formats: tsv, csv, kql, spl, iptables, ufw, nginx.
 *  - csv keeps today's 7-column order (index.php's download-csv handler:
 *    IP, CC, State/Province, City, ASN, ASN Org, Category); Hits and DROP
 *    are appended at the end, never inserted into the middle (D9).
 *  - tsv uses the same 9 columns, tab-separated, for pasting into Excel.
 *  - kql is always `let ips = dynamic([...]); <table> | where <col> in (ips)`,
 *    with a first comment line `// edit table and column`, regardless of
 *    row count. Default placeholders: SigninLogs / IPAddress.
 *  - spl is always an inline `src_ip IN (...)` list, regardless of row
 *    count, with the same edit-me comment convention for the field name.
 *  - iptables/ufw/nginx match today's assets/js/ip2geo-app.js generateRules()
 *    output byte-for-byte (D3.4: these move into the Export menu, but the
 *    text itself doesn't change).
 *
 * UMD: exposes `window.ip2geoExport`, and `module.exports` for Jest.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ip2geoExport = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Azure Monitor's log-alert-rule query property cap (design doc D9): the
  // only documented nearby limit for KQL, so the "over the 64 KB alert-rule
  // limit" note is scoped to that, not to any general KQL query-length cap.
  var ALERT_RULE_LIMIT_BYTES = 64 * 1024;

  var FORMAT_META = {
    tsv:      { label: 'TSV' },
    csv:      { label: 'CSV' },
    kql:      { label: 'KQL (Sentinel)' },
    spl:      { label: 'SPL (Splunk)' },
    iptables: { label: 'iptables' },
    ufw:      { label: 'ufw' },
    nginx:    { label: 'nginx' }
  };

  function csvEscape(val) {
    var s = String(val == null ? '' : val);
    return /[,"\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function tsvEscape(val) {
    return String(val == null ? '' : val).replace(/\t/g, ' ').replace(/\n/g, ' ');
  }

  var COLUMNS = ['ip', 'country', 'region', 'city', 'asn', 'asnOrg', 'category', 'hits', 'drop'];
  var HEADERS = ['IP', 'CC', 'State/Province', 'City', 'ASN', 'ASN Org', 'Category', 'Hits', 'DROP'];

  function delimited(rows, sep, escapeFn) {
    var lines = [HEADERS.map(escapeFn).join(sep)];
    rows.forEach(function (row) {
      lines.push(COLUMNS.map(function (col) {
        var v = row[col];
        if (col === 'drop') v = v ? 'DROP' : '';
        return escapeFn(v);
      }).join(sep));
    });
    return lines.join('\r\n');
  }

  function buildCsv(rows) {
    return '﻿' + delimited(rows, ',', csvEscape);
  }

  function buildTsv(rows) {
    return delimited(rows, '\t', tsvEscape);
  }

  function buildKql(rows, opts) {
    opts = opts || {};
    var table = opts.table || 'SigninLogs';
    var column = opts.column || 'IPAddress';
    var ips = rows.map(function (r) { return '"' + r.ip + '"'; }).join(', ');
    return '// edit table and column\n' +
      'let ips = dynamic([' + ips + ']);\n' +
      table + '\n| where ' + column + ' in (ips)';
  }

  function buildSpl(rows, opts) {
    opts = opts || {};
    var field = opts.field || 'src_ip';
    var ips = rows.map(function (r) { return '"' + r.ip + '"'; }).join(' ');
    return '// edit field name\n' + field + ' IN (' + ips + ')';
  }

  function buildIptables(rows) {
    return rows.map(function (r) { return 'iptables -A INPUT -s ' + r.ip + ' -j DROP'; }).join('\n');
  }

  function buildUfw(rows) {
    return rows.map(function (r) { return 'ufw deny from ' + r.ip + ' to any'; }).join('\n');
  }

  function buildNginx(rows) {
    return 'geo $block_ip {\n    default 0;\n' +
      rows.map(function (r) { return '    ' + r.ip + ' 1;'; }).join('\n') +
      '\n}';
  }

  var BUILDERS = {
    tsv: buildTsv,
    csv: buildCsv,
    kql: buildKql,
    spl: buildSpl,
    iptables: buildIptables,
    ufw: buildUfw,
    nginx: buildNginx
  };

  /**
   * @param {string} format one of the keys in BUILDERS
   * @param {Array<Object>} rows the CURRENT FILTERED rows (D9: export scope
   *   == visible rows, same as applyFilters()'s output)
   * @param {Object} [opts] { table, column } for kql; { field } for spl
   * @returns {string}
   */
  function buildExport(format, rows, opts) {
    var builder = BUILDERS[format];
    if (!builder) throw new Error('Unknown export format: ' + format);
    return builder(rows, opts);
  }

  function approxKB(text) {
    // UTF-8 byte length, not UTF-16 code units — matters once IPv6/org names
    // carry multi-byte characters.
    var bytes = typeof TextEncoder !== 'undefined'
      ? new TextEncoder().encode(text).length
      : unescape(encodeURIComponent(text)).length;
    return bytes;
  }

  /**
   * Export ▾ item label per D9: "KQL (Sentinel) · 3,412 IPs · ~52 KB", plus
   * an "over the 64 KB alert-rule limit" note — shown ONLY for kql, and
   * only when the generated query is actually over that cap.
   *
   * @returns {{label: string, count: number, approxKB: number, text: string, over64kNote: boolean}}
   */
  function exportLabel(format, rows, opts) {
    var text = buildExport(format, rows, opts);
    var bytes = approxKB(text);
    var kb = Math.max(1, Math.round(bytes / 1024));
    var meta = FORMAT_META[format] || { label: format };
    var count = rows.length;
    var over64kNote = format === 'kql' && bytes > ALERT_RULE_LIMIT_BYTES;

    var label = meta.label + ' · ' + count.toLocaleString() + ' IP' + (count === 1 ? '' : 's') + ' · ~' + kb + ' KB';
    return { label: label, count: count, approxKB: kb, text: text, over64kNote: over64kNote };
  }

  /** D9: toast text, aria-live=polite, "Copied N rows as TSV". */
  function toastText(format, rows) {
    var meta = FORMAT_META[format] || { label: format };
    var count = rows.length;
    return 'Copied ' + count.toLocaleString() + ' row' + (count === 1 ? '' : 's') + ' as ' + meta.label.replace(/\s*\(.*\)$/, '');
  }

  return {
    FORMAT_META: FORMAT_META,
    ALERT_RULE_LIMIT_BYTES: ALERT_RULE_LIMIT_BYTES,
    buildExport: buildExport,
    exportLabel: exportLabel,
    toastText: toastText,
    approxKB: approxKB
  };
});
