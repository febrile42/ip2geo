/**
 * Phase 2 workbench: DOM orchestration on top of the pure modules
 * (filters.js, export-templates.js, summary.js, share-link.js) plus
 * extract-ips.js. Progressive enhancement (design doc architecture):
 * intercepts the lookup form submit, extracts IPs in the browser, POSTs
 * JSON to /api/lookup.php in one request, and renders the workbench
 * client-side. Falls back to the normal form POST (the existing
 * render_lookup_results() no-JS path in index.php) on missing JS support
 * or a network/API failure that isn't one of D6's named states.
 *
 * This file is DOM-heavy by nature (it IS the view layer) and isn't
 * required to be pure; the logic it leans on (filtering, export text,
 * summary line, share-link encoding) already is, and is tested separately.
 * Still exposes its render/state helpers via UMD so Jest can reach the
 * few non-DOM pieces (state building, chip-count helpers) directly.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory({
      filters: require('./filters.js'),
      exportTemplates: require('./export-templates.js'),
      summary: require('./summary.js'),
      shareLink: require('./share-link.js')
    });
  } else {
    root.ip2geoWorkbench = factory({
      filters: root.ip2geoFilters,
      exportTemplates: root.ip2geoExport,
      summary: root.ip2geoSummary,
      shareLink: root.ip2geoShareLink
    });
  }
})(typeof self !== 'undefined' ? self : this, function (deps) {
  'use strict';

  var Filters = deps.filters;
  var Exp = deps.exportTemplates;
  var Summary = deps.summary;
  var Share = deps.shareLink;

  var CATEGORY_LABELS = Summary.SUMMARY_CATEGORY_LABELS;
  var RECENT_CHIP_COUNT = 6; // D3.5: top 6 countries + "+N more"
  var NO_COUNTRY_LABEL = 'No country'; // IPG-81: display text for country ''; the filter/share value stays ''
  function countryLabel(code) { return code || NO_COUNTRY_LABEL; }
  var SEARCH_TRACK_DEBOUNCE_MS = 600; // D9: don't fire filter_search per keystroke
  var searchTrackTimer = null;

  // D9: dimension only, never the filter value (no IPs/ASNs/countries the visitor typed or clicked).
  function trackFilterUse(dim) {
    try { window.umami && window.umami.track('filter_' + dim); } catch (e) { /* no-op */ }
  }

  // ── small DOM helpers ───────────────────────────────────────────────────

  // Same text as DROP_EXPLAINER in includes/summary.php (tests/DropExplainerTest.php).
  var DROP_EXPLAINER = 'Spamhaus DROP (Don\'t Route Or Peer): this IP is in a netblock Spamhaus lists as hijacked or run by spam or cybercrime operations. Legitimate traffic from these ranges is rare.';

  // IPG-42/M1 copy (Bilac, IPG-50; verified against the code by Psyger, IPG-51) — verbatim, do not reword.
  var SHARE_DISCLOSURE = 'The IPs are in the link itself, not saved on our server. Anyone with the link can see them.';
  var SHARE_OVER_CAP_NOTICE = 'Filter to fewer IPs to get a link, or download the view file and send that. To open it, the recipient pastes the file\'s contents into ip2geo.';

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      if (k === 'class') e.className = attrs[k];
      else if (k === 'text') e.textContent = attrs[k];
      else if (k.indexOf('on') === 0 && typeof attrs[k] === 'function') e.addEventListener(k.slice(2), attrs[k]);
      else e.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) {
      if (c == null) return;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return e;
  }

  function formatLookupTime(ms) {
    var r = Math.round(ms);
    if (r < 1) return '<1 ms';
    if (r < 1000) return r + ' ms';
    return (ms / 1000).toFixed(2) + ' s';
  }

  // Single source of truth for the "N IPv4 / M IPv6" phrasing so the paste
  // pill and the loading line can't drift apart (IPG-34/IPG-39).
  function formatIpSplit(v4, v6) {
    if (v4 && v6) return v4.toLocaleString('en-US') + ' IPv4 / ' + v6.toLocaleString('en-US') + ' IPv6';
    if (v6) return v6.toLocaleString('en-US') + ' IPv6';
    return v4.toLocaleString('en-US') + ' IPv4';
  }

  function ipv6MiddleTruncate(ip) {
    // Mirrors index.php's ipv6_middle_truncate(): "2001:db8::7334" -> "2001:db8…:7334".
    if (ip.length <= 15) return ip;
    return ip.slice(0, 8) + '…:' + ip.slice(-4);
  }

  function catColor(category) {
    return {
      scanning: 'var(--verdict-high)',
      vpn: 'var(--verdict-moderate)',
      residential: 'var(--verdict-low)',
      cloud: 'var(--verdict-cloud)',
      unknown: 'var(--verdict-unknown)'
    }[category] || 'var(--verdict-unknown)';
  }

  // ── row model ────────────────────────────────────────────────────────

  /**
   * Combine api/lookup.php's {results, unresolved} with the client-side
   * per-IP hit counts from extractIps() into the row shape filters.js /
   * export-templates.js / share-link.js all expect.
   */
  function buildRows(apiResults, hitCounts) {
    return apiResults.map(function (r) {
      return {
        ip: r.ip,
        country: r.country_iso_code || '',
        countryName: r.country_name || '',
        region: r.subdivision_1_name || '',
        city: r.city_name || '',
        asn: r.autonomous_system_number != null ? 'AS' + r.autonomous_system_number : '',
        asnOrg: r.autonomous_system_org || '',
        category: r.category || 'unknown',
        drop: !!r.drop,
        hits: (hitCounts && hitCounts[r.ip]) || 1
      };
    });
  }

  // ── state ────────────────────────────────────────────────────────────

  function makeState() {
    return {
      rows: [],
      unresolved: [],
      filters: Filters.emptyState(),
      sort: { key: 'hits', dir: 'desc' },
      pasteMeta: { lines: 0, v4: 0, v6: 0, overCap: false, lookupMs: null, rawText: '' },
      recipient: null // {count, categories, countries} when opened from a share link
    };
  }

  // ── summary line (D4/D5: fixed, not filter-driven — always describes
  // every resolved IP in the lookup) ──────────────────────────────────────

  function renderSummary(root, state) {
    var host = root.querySelector('.wb-summary');
    if (!host) return;
    host.innerHTML = '';

    // Table rows name the org field asnOrg; buildSummary() (a port of
    // includes/summary.php) reads asn_org. Without this map every org was blank.
    var summary = Summary.buildSummary(state.rows.map(function (r) {
      return { category: r.category, asn: r.asn, asn_org: r.asnOrg, drop: r.drop };
    }));

    var hasFacts = summary.drop_count > 0 || summary.top_asn !== null;
    host.hidden = !hasFacts;
    if (!hasFacts) return;

    if (summary.drop_count > 0) {
      var n = el('span', { class: 'lookup-summary-n' }, [summary.drop_count.toLocaleString('en-US')]);
      var dropAbbr = el('abbr', { title: DROP_EXPLAINER }, ['Spamhaus DROP']);
      var dropChildren = summary.drop_count === 1
        ? [n, ' IP in a ', dropAbbr, ' netblock']
        : [n, ' IPs in ', dropAbbr, ' netblocks'];
      host.appendChild(el('span', { class: 'lookup-summary-fact lookup-summary-drop' }, dropChildren));
    }

    if (summary.top_asn !== null) {
      var asnText = (summary.top_asn.asn + ' ' + summary.top_asn.org).trim();
      host.appendChild(el('span', { class: 'lookup-summary-fact lookup-summary-asns' }, [
        'Top ASN: ',
        el('span', { class: 'lookup-summary-asn' }, [asnText]),
        ' (',
        el('span', { class: 'lookup-summary-n' }, [summary.top_asn.count.toLocaleString('en-US')]),
        ' IPs)'
      ]));
    }
  }

  // ── unresolved IPs toggle ────────────────────────────────────────────

  function renderUnresolved(root, state) {
    var btn = root.querySelector('.wb-toggle-unresolved');
    var body = root.querySelector('.wb-unresolved-rows');
    if (!btn || !body) return;

    var n = state.unresolved.length;
    if (n === 0) {
      btn.hidden = true;
      body.hidden = true;
      body.innerHTML = '';
      return;
    }

    btn.hidden = false;
    body.innerHTML = '';
    state.unresolved.forEach(function (ip) {
      body.appendChild(el('tr', { class: 'wb-unresolved-row' }, [
        el('td', {}, [ip]), el('td', {}, []), el('td', {}, []), el('td', {}, []),
        el('td', {}, []), el('td', {}, []), el('td', {}, []), el('td', {}, [])
      ]));
    });

    function setLabel(shown) {
      btn.textContent = (shown ? 'Hide ' : 'Show ') + n.toLocaleString('en-US') + ' unresolved IP' + (n === 1 ? '' : 's');
    }
    body.hidden = true;
    setLabel(false);
    btn.onclick = function () {
      body.hidden = !body.hidden;
      setLabel(!body.hidden);
    };
  }

  // ── toast (design doc: role=status, --surface-2, --r-md, D9) ───────────

  function showToast(root, text) {
    var host = root.querySelector('.wb-toast-host');
    var toast = el('div', { class: 'wb-toast', role: 'status', 'aria-live': 'polite' }, [text]);
    host.appendChild(toast);
    window.setTimeout(function () {
      toast.classList.add('wb-toast--out');
      window.setTimeout(function () { toast.remove(); }, 200);
    }, 3000);
  }

  // ── Export ▾ menu (D9 + D16 WAI-ARIA menu button pattern) ───────────────

  var EXPORT_GROUPS = [
    { id: 'wb-menu-g-data', label: 'Data & queries', formats: ['tsv', 'csv', 'kql', 'spl'] },
    { id: 'wb-menu-g-rules', label: 'Block rules', formats: ['iptables', 'ufw', 'nginx'] }
  ];

  function renderExportMenu(root, state, visibleRows) {
    var wrap = root.querySelector('.wb-export');
    wrap.innerHTML = '';

    var count = visibleRows.length;
    var btn = el('button', {
      class: 'button small wb-export-btn',
      type: 'button',
      'aria-haspopup': 'true',
      'aria-expanded': 'false',
      id: 'wb-export-btn'
    }, [
      'Export / Rules ',
      el('span', { 'aria-hidden': 'true' }, ['▾']),
      el('span', { class: 'wb-export-count' }, [count.toLocaleString('en-US') + ' IPs'])
    ]);

    var menu = el('div', { class: 'wb-menu', role: 'menu', 'aria-labelledby': 'wb-export-btn', hidden: 'hidden' });

    EXPORT_GROUPS.forEach(function (group) {
      var groupEl = el('div', { class: 'wb-menu-group', role: 'group', 'aria-labelledby': group.id }, [
        el('div', { class: 'wb-menu-group-label', id: group.id, role: 'presentation' }, [group.label])
      ]);
      group.formats.forEach(function (format) {
        var info = Exp.exportLabel(format, visibleRows);
        var item = el('button', {
          class: 'wb-menu-item',
          type: 'button',
          role: 'menuitem',
          tabindex: '-1'
        }, [
          el('span', {}, [info.label]),
          info.over64kNote ? el('span', { class: 'wb-menu-note' }, ['over the 64 KB alert-rule limit']) : null
        ]);
        item.addEventListener('click', function () {
          copyExport(root, format, visibleRows);
          closeMenu();
        });
        groupEl.appendChild(item);
      });
      menu.appendChild(groupEl);
    });

    wrap.appendChild(btn);
    wrap.appendChild(menu);

    function items() { return Array.from(menu.querySelectorAll('.wb-menu-item')); }

    function openMenu() {
      menu.hidden = false;
      btn.setAttribute('aria-expanded', 'true');
      var first = items()[0];
      if (first) first.focus();
      document.addEventListener('click', onDocClick, true);
    }
    function closeMenu(returnFocus) {
      menu.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
      document.removeEventListener('click', onDocClick, true);
      if (returnFocus) btn.focus();
    }
    function onDocClick(e) {
      if (!wrap.contains(e.target)) closeMenu();
    }

    btn.addEventListener('click', function () {
      if (menu.hidden) openMenu(); else closeMenu();
    });
    btn.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openMenu();
      }
    });
    menu.addEventListener('keydown', function (e) {
      var list = items();
      var idx = list.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        list[(idx + 1) % list.length].focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        list[(idx - 1 + list.length) % list.length].focus();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        closeMenu(true);
      } else if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        document.activeElement.click();
      } else if (e.key === 'Tab') {
        closeMenu();
      }
    });
  }

  function copyExport(root, format, rows) {
    var text = Exp.buildExport(format, rows);
    var done = function () {
      showToast(root, Exp.toastText(format, rows));
      try { window.umami && window.umami.track('copy_export_' + format); } catch (e) { /* no-op */ }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, done);
    } else {
      done();
    }
  }

  // ── chips (D10 + D16: native checkboxes, visible focus, aria-label) ────

  function renderChipRow(root, selector, dim, label, allValues, counts, state, onChange) {
    var wrap = root.querySelector(selector);
    // The search box (categories row only) is created once and never
    // removed from the DOM on re-render: detaching a focused element (even
    // via appendChild to move it) blurs it, which is what dropped focus and
    // caret position after every keystroke (IPG-29). Everything else in
    // this row is rebuilt fresh each render, inserted before the cached
    // search node so it keeps its place at the end of the row.
    var search = wrap._wbSearch;

    Array.prototype.slice.call(wrap.childNodes).forEach(function (node) {
      if (node !== search) wrap.removeChild(node);
    });

    function append(node) {
      if (search) wrap.insertBefore(node, search);
      else wrap.appendChild(node);
    }

    append(el('span', { class: 'wb-chip-label' }, [label]));

    var shown = dim === 'countries' ? allValues.slice(0, RECENT_CHIP_COUNT) : allValues;
    var rest = dim === 'countries' ? allValues.slice(RECENT_CHIP_COUNT) : [];

    shown.forEach(function (value) {
      var selected = state.filters[dim].has(value);
      var count = counts[value] || 0;
      var text = dim === 'categories' ? (CATEGORY_LABELS[value] || value) : countryLabel(value);
      var chipLabel = el('label', { class: 'wb-chip' + (selected ? ' wb-chip--sel' : '') }, [
        el('input', {
          type: 'checkbox',
          checked: selected ? 'checked' : null,
          'aria-label': text + ', ' + count + ' IPs',
          onchange: function () { /* handled on the wrapping click below for gesture info */ }
        }),
        selected ? '✓ ' : '',
        text,
        el('i', {}, [' ' + count])
      ]);
      var input = chipLabel.querySelector('input');
      if (!selected) input.removeAttribute('checked');

      chipLabel.addEventListener('click', function (e) {
        e.preventDefault();
        var gesture = { shift: e.shiftKey, ctrl: e.ctrlKey || e.metaKey };
        onChange(value, gesture);
      });
      chipLabel.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onChange(value, { shift: e.shiftKey, ctrl: e.ctrlKey || e.metaKey });
        }
      });
      append(chipLabel);
    });

    if (rest.length > 0) {
      append(el('span', { class: 'wb-chip wb-chip--more', text: '+' + rest.length + ' more' }));
    }

    if (dim === 'categories') {
      if (!search) {
        search = el('input', {
          type: 'search',
          class: 'wb-search',
          placeholder: 'Filter IP, ASN, org…',
          'aria-label': 'Filter results by IP, ASN or organization'
        });
        search.addEventListener('input', function () {
          var current = wrap._wbState;
          current.filters = { categories: current.filters.categories, countries: current.filters.countries, search: search.value };
          window.clearTimeout(searchTrackTimer);
          searchTrackTimer = window.setTimeout(function () { trackFilterUse('search'); }, SEARCH_TRACK_DEBOUNCE_MS);
          renderAll(root, current);
        });
        wrap.appendChild(search);
        wrap._wbSearch = search;
      }
      wrap._wbState = state;
      if (search.value !== state.filters.search) search.value = state.filters.search;
    }
  }

  // ── table (windowed rendering so 10k rows stay responsive) ─────────────

  var ROW_WINDOW = 300; // initial + per-scroll-batch row count

  function renderTable(root, state, visibleRows) {
    var sorted = visibleRows.slice().sort(function (a, b) {
      var dir = state.sort.dir === 'asc' ? 1 : -1;
      if (a[state.sort.key] < b[state.sort.key]) return -1 * dir;
      if (a[state.sort.key] > b[state.sort.key]) return 1 * dir;
      return 0;
    });

    var tbody = root.querySelector('.wb-table tbody');
    tbody.innerHTML = '';
    var sentinel = root.querySelector('.wb-table-sentinel');

    var rendered = 0;
    function renderMore() {
      var frag = document.createDocumentFragment();
      var end = Math.min(rendered + ROW_WINDOW, sorted.length);
      for (var i = rendered; i < end; i++) {
        frag.appendChild(renderRow(sorted[i]));
      }
      tbody.appendChild(frag);
      rendered = end;
      if (sentinel) sentinel.textContent = rendered < sorted.length ? 'Scroll for more (' + (sorted.length - rendered) + ' remaining)' : '';
    }
    renderMore();

    if (root._wbObserver) root._wbObserver.disconnect();
    if (sentinel && 'IntersectionObserver' in window) {
      root._wbObserver = new IntersectionObserver(function (entries) {
        if (entries[0].isIntersecting && rendered < sorted.length) renderMore();
      });
      root._wbObserver.observe(sentinel);
    } else {
      // No IntersectionObserver (older browser, or a test env): render everything.
      renderMore();
      while (rendered < sorted.length) renderMore();
    }

    var th = root.querySelector('.wb-table th[data-key="' + state.sort.key + '"]');
    root.querySelectorAll('.wb-table th[aria-sort]').forEach(function (h) { h.removeAttribute('aria-sort'); h.setAttribute('aria-sort', 'none'); });
    if (th) th.setAttribute('aria-sort', state.sort.dir === 'asc' ? 'ascending' : 'descending');
  }

  function renderRow(row) {
    var isV6 = row.ip.indexOf(':') !== -1;
    var ipCell;
    if (isV6) {
      ipCell = el('td', { class: 'cell-ip', title: row.ip }, [
        el('span', { class: 'ip-full' }, [row.ip]),
        el('span', { class: 'ip-truncated' }, [ipv6MiddleTruncate(row.ip)])
      ]);
    } else {
      ipCell = el('td', { class: 'cell-ip' }, [row.ip]);
    }

    var catCell = el('td', {}, [
      el('span', { class: 'wb-cat', style: 'background:' + catColor(row.category) }, [CATEGORY_LABELS[row.category] || row.category]),
      row.drop ? el('abbr', { class: 'drop-tag', title: DROP_EXPLAINER }, ['DROP']) : null
    ]);

    return el('tr', { 'data-category': row.category, 'data-country': row.country }, [
      ipCell,
      el('td', {}, [row.country]),
      el('td', { class: 'cell-region' }, [row.region]),
      el('td', { class: 'cell-city' }, [row.city]),
      el('td', { class: 'mono' }, [row.asn]),
      el('td', { class: 'cell-asn-org', title: row.asnOrg }, [row.asnOrg]),
      catCell,
      el('td', { class: 'num' }, [String(row.hits)])
    ]);
  }

  // ── full render ──────────────────────────────────────────────────────

  function renderAll(root, state) {
    var visible = Filters.applyFilters(state.rows, state.filters);
    var counts = Filters.chipCounts(state.rows, state.filters);

    var categoryOrder = Object.keys(CATEGORY_LABELS).filter(function (c) { return counts.categories[c] || state.filters.categories.has(c); });
    var countryOrder = Object.keys(counts.countries).sort(function (a, b) { return (counts.countries[b] || 0) - (counts.countries[a] || 0); });

    renderChipRow(root, '.wb-chips-category', 'categories', 'Category', categoryOrder, counts.categories, state, function (value, gesture) {
      state.filters = { categories: Filters.chipClick(state.filters.categories, value, gesture), countries: state.filters.countries, search: state.filters.search };
      trackFilterUse('category');
      renderAll(root, state);
    });
    renderChipRow(root, '.wb-chips-country', 'countries', 'Country', countryOrder, counts.countries, state, function (value, gesture) {
      state.filters = { categories: state.filters.categories, countries: Filters.chipClick(state.filters.countries, value, gesture), search: state.filters.search };
      trackFilterUse('country');
      renderAll(root, state);
    });

    renderExportMenu(root, state, visible);
    renderTable(root, state, visible);

    var shownEl = root.querySelector('.wb-shown-count');
    shownEl.textContent = visible.length.toLocaleString('en-US') + ' shown';

    var clearBtn = root.querySelector('.wb-clear-filters');
    var hasFilter = state.filters.categories.size > 0 || state.filters.countries.size > 0;
    clearBtn.hidden = !hasFilter;
    clearBtn.onclick = function () {
      state.filters = Filters.clearFilters(state.filters);
      renderAll(root, state);
      // The button hides itself; hand focus to the search field so keyboard users aren't dropped on <body>.
      var search = root.querySelector('.wb-search');
      if (search) search.focus();
    };

    var shareBtn = root.querySelector('.wb-share-btn');
    var shareResult = Share.buildShareLink({
      ips: visible.map(function (r) { return r.ip; }),
      categories: Array.from(state.filters.categories),
      countries: Array.from(state.filters.countries),
      search: state.filters.search
    });
    shareBtn.classList.toggle('wb-share-btn--disabled', shareResult.overCap);
    if (shareResult.overCap) {
      shareBtn.textContent = Share.overCapLabel(visible.length);
      shareBtn.disabled = true;
    } else {
      shareBtn.textContent = 'Copy share link · ' + visible.length.toLocaleString('en-US') + ' IPs';
      shareBtn.disabled = false;
    }
    shareBtn.onclick = function () {
      if (shareResult.overCap) return;
      var url = window.location.origin + window.location.pathname + '#v=' + shareResult.payload;
      var done = function () {
        showToast(root, 'Link copied · ' + visible.length.toLocaleString('en-US') + ' IPs');
        try { window.umami && window.umami.track('share_link_created'); } catch (e) { /* no-op */ }
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(done, done);
      } else {
        done();
      }
    };

    var shareNotice = root.querySelector('.wb-share-notice');
    shareNotice.textContent = shareResult.overCap ? SHARE_OVER_CAP_NOTICE : SHARE_DISCLOSURE;

    var downloadBtn = root.querySelector('.wb-share-download');
    downloadBtn.hidden = !shareResult.overCap;
    downloadBtn.onclick = function () {
      var json = Share.buildViewFile({
        ips: visible.map(function (r) { return r.ip; }),
        categories: Array.from(state.filters.categories),
        countries: Array.from(state.filters.countries),
        search: state.filters.search
      });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
      a.download = 'view.ip2geo.json';
      a.click();
      URL.revokeObjectURL(a.href);
    };

    var emptyMsg = root.querySelector('.wb-empty-filter');
    emptyMsg.hidden = visible.length !== 0 || state.rows.length === 0;
  }

  // ── paste bar ────────────────────────────────────────────────────────

  function renderPasteBar(root, state, onEdit) {
    var bar = root.querySelector('.wb-paste-bar');
    bar.innerHTML = '';
    var m = state.pasteMeta;
    // Read-only getter for the Recent-lookups module (ip2geo-app.js), so it
    // can tell whether the textarea holds unsent text without reaching into
    // workbench state directly.
    root._wbLastRawText = function () { return m.rawText; };

    var pillChildren = [];
    if (m.lines != null) {
      pillChildren.push(el('span', {}, [m.lines.toLocaleString('en-US') + ' line' + (m.lines === 1 ? '' : 's')]));
      pillChildren.push(' · ');
    }
    var label = m.overCap ? 'Looked up: ' : 'Unique: ';
    pillChildren.push(el('span', {}, [label + formatIpSplit(m.v4, m.v6)]));
    bar.appendChild(el('span', { class: 'wb-paste-pill' }, pillChildren));

    if (!state.recipient) {
      bar.appendChild(el('button', { type: 'button', class: 'button small', 'aria-controls': 'message', onclick: onEdit }, ['Edit paste']));
    }
    if (m.lookupMs != null && isFinite(m.lookupMs) && m.lookupMs >= 0) {
      bar.appendChild(el('span', { class: 'wb-paste-time' }, ['looked up in ' + formatLookupTime(m.lookupMs)]));
    }

    // The over-cap notice is set on pasteMeta in startLookup but rendered
    // here, right after the bar; drop any stale one from a previous render
    // before deciding whether to add a fresh one (IPG-39).
    var existingNotice = root.querySelector('.wb-overcap');
    if (existingNotice) existingNotice.remove();
    if (m.overCapNotice) {
      var notice = el('p', { class: 'notice wb-overcap', role: 'status' }, [m.overCapNotice]);
      bar.parentNode.insertBefore(notice, bar.nextSibling);
    }
  }

  // ── D6 lookup states, rendered into the results slot, never alert() ────

  function renderState(root, kind, message, opts) {
    opts = opts || {};
    var slot = root.querySelector('.wb-state');
    slot.innerHTML = '';
    slot.hidden = false;
    root.querySelector('.wb-body').hidden = true;
    var role = (kind === 'error' || kind === '429' || kind === '503' || kind === 'network') ? 'alert' : 'status';
    var p = el('p', { class: 'notice wb-notice--' + kind, role: role }, [message]);
    slot.appendChild(p);
    if (opts.retry) {
      var retryBtn = el('button', { type: 'button', class: 'button small' }, ['Retry']);
      retryBtn.addEventListener('click', opts.retry);
      slot.appendChild(retryBtn);
    }
  }

  function clearState(root) {
    var slot = root.querySelector('.wb-state');
    slot.hidden = true;
    slot.innerHTML = '';
    root.querySelector('.wb-body').hidden = false;
  }

  /**
   * Runs one lookup: POSTs {ips} to /api/lookup.php and renders every D6
   * state (LOADING while in flight, 429/503/network/other error, or the
   * full workbench on success). uniqueIps is the deduped IP list;
   * hitCounts maps ip -> occurrence count from extractIps().
   *
   * @returns {Promise<boolean>} true on success, false if it fell through
   *   to a D6 error state (caller decides whether to fall back to the
   *   plain form POST for anything that isn't one of those named states).
   */
  function runLookup(root, state, uniqueIps, hitCounts, meta) {
    state.pasteMeta = meta;
    renderState(root, 'loading', 'Looking up ' + formatIpSplit(meta.v4, meta.v6) + '…');

    var startedAt = (window.performance && performance.now) ? performance.now() : Date.now();
    return fetch('/api/lookup.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: uniqueIps })
    }).then(function (resp) {
      if (resp.status === 429) {
        var retryAfter = resp.headers.get('Retry-After') || '60';
        renderState(root, '429', 'Too many lookups from your network. Try again in ' + retryAfter + 's.');
        return false;
      }
      if (resp.status === 503) {
        renderState(root, '503', 'Lookup data is updating. Try again in a minute.');
        return false;
      }
      if (!resp.ok) {
        return resp.json().catch(function () { return {}; }).then(function () {
          renderState(root, 'error', 'Couldn’t reach ip2geo. Your paste is still here.', {
            retry: function () { runLookup(root, state, uniqueIps, hitCounts, meta); }
          });
          return false;
        });
      }
      return resp.json().then(function (data) {
        state.rows = buildRows(data.results || [], hitCounts);
        state.unresolved = data.unresolved || [];
        var finishedAt = (window.performance && performance.now) ? performance.now() : Date.now();
        meta.lookupMs = finishedAt - startedAt;
        state.pasteMeta = meta;
        clearState(root);
        renderPasteBar(root, state, root._wbOnEdit);
        renderSummary(root, state);
        renderUnresolved(root, state);
        renderAll(root, state);
        return true;
      });
    }).catch(function () {
      renderState(root, 'network', 'Couldn’t reach ip2geo. Your paste is still here.', {
        retry: function () { runLookup(root, state, uniqueIps, hitCounts, meta); }
      });
      return false;
    });
  }

  /**
   * Wires the paste form's submit to the browser extract -> API -> render
   * pipeline (architecture: progressive enhancement). Falls back to a real
   * form submit (the PHP no-JS path) when window.extractIps is missing, or
   * when the paste is EMPTY/PRIVATE-ONLY/OVER-2MB — those are handled by
   * rendering the D6 message directly rather than round-tripping the
   * server, EXCEPT that this function only owns the JS-available path;
   * the caller decides whether to call preventDefault() at all.
   */
  function mount(root, form, textarea) {
    // IPG-32: the D12 "Firewall rules moved here" hint is gone; drop its leftover timestamp.
    try { window.localStorage && window.localStorage.removeItem('wb_export_hint_seen_at'); } catch (e) { /* storage blocked */ }

    var state = makeState();

    if (typeof window.extractIps !== 'function') {
      return null; // no JS extractor available: caller should leave the form to submit normally
    }

    root._wbOnEdit = function () {
      var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      var end = textarea.value.length;
      textarea.focus({ preventScroll: true });
      textarea.setSelectionRange(end, end);      // caret at the end, nothing selected
      textarea.scrollTop = textarea.scrollHeight; // show the end of a long paste inside the box
      textarea.scrollIntoView({ block: 'center', behavior: reduce ? 'auto' : 'smooth' });
    };

    function startLookup(rawText, opts) {
      opts = opts || {};
      if (rawText.length > 2097152) {
        root.hidden = false;
        renderState(root, 'error', 'Paste is over 2 MB. Trim it or paste the busiest part of the log.');
        return Promise.resolve(false);
      }

      var extracted = window.extractIps(rawText);
      var lines = rawText.split('\n').length;

      if (extracted.ips.length === 0) {
        root.hidden = false;
        renderState(root, 'empty', 'No IP addresses found in the pasted text.');
        return Promise.resolve(false);
      }

      var hitCounts = {};
      var uniqueIps = extracted.ips.map(function (pair) {
        hitCounts[pair[0]] = pair[1];
        return pair[0];
      });

      // extracted.v6Count is post-cap (counts only the IPs actually looked
      // up), but extracted.totalUnique is pre-cap: deriving v4 from
      // totalUnique here would make v4 + v6 disagree with the looked-up
      // count whenever the cap trimmed the list (IPG-39 count bug).
      var v6 = extracted.v6Count;
      var v4 = uniqueIps.length - v6;
      var overCap = extracted.totalUnique > uniqueIps.length;
      var meta = { lines: lines, v4: v4, v6: v6, overCap: overCap, lookupMs: null, rawText: rawText };
      if (overCap) {
        var skipped = extracted.totalUnique - uniqueIps.length;
        meta.overCapNotice = 'Looked up the first ' + uniqueIps.length.toLocaleString('en-US') + ' of ' +
          extracted.totalUnique.toLocaleString('en-US') + ' unique IPs. ' + skipped.toLocaleString('en-US') +
          ' skipped. Paste the rest separately to check them.';
      }

      root.hidden = false;
      var isSample = !!window.__ip2geoSampleActive;
      window.__ip2geoSampleActive = false;

      return runLookup(root, state, uniqueIps, hitCounts, meta).then(function (ok) {
        if (ok) {
          // Matches the bucket boundaries the old server-fragment AJAX handler
          // used (index.php, before the workbench replaced it) so the
          // `lookup_submit` event's ip_count_bucket values stay consistent
          // across the cutover for ip2geo-admin's dashboards.
          var uniqueCount = extracted.totalUnique;
          var bucket = uniqueCount === 1 ? '1'
                     : uniqueCount <= 10 ? '2-10'
                     : uniqueCount <= 50 ? '11-50'
                     : uniqueCount <= 100 ? '51-100'
                     : uniqueCount <= 500 ? '101-500'
                     : uniqueCount <= 1000 ? '501-1000'
                     : uniqueCount <= 5000 ? '1001-5000'
                     : '5000+';
          try { window.umami && window.umami.track('lookup_submit', { ip_count_bucket: bucket, sample: isSample }); } catch (e) { /* no-op */ }

          // Recent-lookups (assets/js/ip2geo-app.js's handleLookupSubmit) listens
          // for this same event name; it no-ops when the opt-in is off.
          try {
            document.dispatchEvent(new CustomEvent('ip2geo:lookup_submit', { detail: { ips: uniqueIps, count: uniqueCount } }));
          } catch (e) { /* no-op */ }
        }
        return ok;
      });
    }

    var handle = { state: state, startLookup: startLookup };

    // Calls handle.startLookup (not the closed-over startLookup directly) so
    // a caller can wrap handle.startLookup after mount() returns — e.g.
    // index.php's bootstrap wraps it to hide the PHP-rendered #results and
    // scroll to the workbench on success — and have that wrapper actually
    // run on submit.
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      handle.startLookup(textarea.value);
    });

    return handle;
  }

  /**
   * D8 recipient path: decode a #v= payload captured by R3's inline script
   * (window.__ip2geoSharedView, set before the Umami tracker loads) and
   * re-run the lookup via the API, same D6 states, with a recipient banner.
   */
  function mountSharedView(root, payload, onRestoreBanner) {
    var decoded = Share.decodeShareState(payload);
    if (!decoded) return Promise.resolve(false); // callers chain .then()

    var hitCounts = {};
    decoded.ips.forEach(function (ip) { hitCounts[ip] = 1; });
    var v6Count = decoded.ips.filter(function (ip) { return ip.indexOf(':') !== -1; }).length;
    var meta = { lines: null, v4: decoded.ips.length - v6Count, v6: v6Count, lookupMs: null, rawText: decoded.ips.join('\n') };

    var state = makeState();
    state.recipient = { count: decoded.ips.length, categories: decoded.categories, countries: decoded.countries };
    root.hidden = false;

    if (onRestoreBanner) {
      onRestoreBanner('Shared view · ' + decoded.ips.length.toLocaleString('en-US') + ' IPs' +
        (decoded.categories.length || decoded.countries.length
          ? ' · filters: ' + decoded.categories.map(function (c) { return CATEGORY_LABELS[c] || c; })
              .concat(decoded.countries.map(countryLabel)).join(', ')
          : ''));
    }

    return runLookup(root, state, decoded.ips, hitCounts, meta).then(function (ok) {
      if (ok) {
        state.filters = {
          categories: new Set(decoded.categories),
          countries: new Set(decoded.countries),
          search: decoded.search || ''
        };
        renderSummary(root, state);
        renderUnresolved(root, state);
        renderAll(root, state);
      }
      return ok;
    });
  }

  // ── public API (also what Jest reaches through the UMD export) ─────────

  return {
    buildRows: buildRows,
    makeState: makeState,
    renderAll: renderAll,
    renderSummary: renderSummary,
    renderUnresolved: renderUnresolved,
    formatLookupTime: formatLookupTime,
    formatIpSplit: formatIpSplit,
    renderPasteBar: renderPasteBar,
    renderState: renderState,
    clearState: clearState,
    ipv6MiddleTruncate: ipv6MiddleTruncate,
    runLookup: runLookup,
    mount: mount,
    mountSharedView: mountSharedView
  };
});
