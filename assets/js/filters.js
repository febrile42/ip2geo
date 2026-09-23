/**
 * Pure filter state + reducer for the Phase 2 workbench (design doc D10,
 * R14). Deliberately has no DOM in it — assets/js/workbench.js renders
 * state produced here; tests/js/filters.test.js exercises it directly.
 *
 * State shape: { categories: Set<string>, countries: Set<string>, search: string }
 * "Selected" set empty for a dimension means "no filter on that dimension",
 * i.e. everything passes it (D10: "all chips start unselected, meaning
 * everything is shown" — the opposite of today's PHP/ip2geo-app.js chips,
 * where an empty *checked* set hides everything; see
 * tests/js/filters-characterization.test.js for that old behavior and its
 * header comment for the full list of intentional differences).
 *
 * Row shape (design doc Approved Mockup table + api/lookup.php response):
 *   { ip, country, region, city, asn, asnOrg, category, drop, hits }
 * Only ip/country/category/asn/asnOrg/hits are read here.
 *
 * UMD: exposes `window.ip2geoFilters` in the browser, `module.exports` for
 * Jest's `require()` — same pattern as extract-ips.js.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ip2geoFilters = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function emptyState() {
    return { categories: new Set(), countries: new Set(), search: '' };
  }

  /**
   * D10 chip reducer, one rule shared by the category row and the country
   * row: plain click on an unselected chip replaces the whole selection
   * with just that chip ("show only this"); plain click on an already
   * selected chip removes it; Shift/Ctrl+click toggles the chip in/out of
   * the current selection without touching the rest.
   *
   * @param {Set<string>} selected current selection for one dimension
   * @param {string} value the clicked chip's value
   * @param {{shift?: boolean, ctrl?: boolean}} [gesture]
   * @returns {Set<string>} a new Set (selected is never mutated)
   */
  function chipClick(selected, value, gesture) {
    gesture = gesture || {};
    var next = new Set(selected);

    if (gesture.shift || gesture.ctrl) {
      if (next.has(value)) {
        next.delete(value);
      } else {
        next.add(value);
      }
      return next;
    }

    if (next.has(value)) {
      next.delete(value);
      return next;
    }

    return new Set([value]);
  }

  /** D10: "Clear filters" resets both chip rows to "everything shown". Search is left alone — it's not a chip. */
  function clearFilters(state) {
    return { categories: new Set(), countries: new Set(), search: state ? state.search : '' };
  }

  function matchesSearch(row, search) {
    if (!search) return true;
    var needle = search.toLowerCase();
    var haystacks = [row.ip, row.asn, row.asnOrg, row.country];
    for (var i = 0; i < haystacks.length; i++) {
      var h = haystacks[i];
      if (typeof h === 'string' && h.toLowerCase().indexOf(needle) !== -1) {
        return true;
      }
    }
    return false;
  }

  /**
   * rows shown = selected categories ∩ selected countries ("none" = all),
   * further narrowed by the search box over IP/ASN/org/country (R14/D10).
   *
   * @param {Array<Object>} rows
   * @param {{categories: Set<string>, countries: Set<string>, search: string}} state
   * @returns {Array<Object>} the subset of rows that should be visible —
   *   this is also, per D10/D9, the exact scope for "N shown", CSV and
   *   every Export ▾ template and the share-link payload.
   */
  function applyFilters(rows, state) {
    state = state || emptyState();
    var categories = state.categories || new Set();
    var countries = state.countries || new Set();
    var search = state.search || '';

    return rows.filter(function (row) {
      var categoryOk = categories.size === 0 || categories.has(row.category);
      var countryOk = countries.size === 0 || countries.has(row.country);
      return categoryOk && countryOk && matchesSearch(row, search);
    });
  }

  /**
   * Per-chip counts against the CURRENT filtered set, cross-filtered the
   * same way the old ip2geo-app.js did (design doc doesn't change this):
   * a category chip's count is how many rows would show if only the
   * country filter (and search) were applied, and vice versa. Used to
   * render the "(N)" next to each chip without it collapsing to 0 once
   * that chip's own dimension is filtered.
   *
   * @returns {{categories: Object<string, number>, countries: Object<string, number>}}
   */
  function chipCounts(rows, state) {
    state = state || emptyState();
    var countries = state.countries || new Set();
    var categories = state.categories || new Set();
    var search = state.search || '';

    var catCounts = {};
    var countryCounts = {};

    rows.forEach(function (row) {
      if (!matchesSearch(row, search)) return;

      var countryOk = countries.size === 0 || countries.has(row.country);
      var categoryOk = categories.size === 0 || categories.has(row.category);

      if (countryOk) {
        catCounts[row.category] = (catCounts[row.category] || 0) + 1;
      }
      if (categoryOk) {
        countryCounts[row.country] = (countryCounts[row.country] || 0) + 1;
      }
    });

    return { categories: catCounts, countries: countryCounts };
  }

  return {
    emptyState: emptyState,
    chipClick: chipClick,
    clearFilters: clearFilters,
    applyFilters: applyFilters,
    chipCounts: chipCounts
  };
});
