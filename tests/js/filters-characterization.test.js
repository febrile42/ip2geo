/**
 * R14 (design doc D5 = A): characterization tests for TODAY's filter-chip
 * behavior in assets/js/ip2geo-app.js (~lines 190-306), captured BEFORE the
 * Phase 2 workbench rewrite touches any chip code.
 *
 * Purpose: lock in current behavior so the rewrite (assets/js/filters.js's
 * pure applyFilters(rows, state), tested separately in filters.test.js) can
 * be checked against it. Intentional differences the Phase 2 rewrite
 * introduces (D10) are listed below and are NOT re-asserted here — they are
 * new behavior, not a regression of the old.
 *
 * Behaviors characterized:
 *  - Country chips: default all checked (= no filter active).
 *  - Country solo click: unchecks every other country chip, checks only the
 *    clicked one, and fires `filter_country` (no properties, R9/D8).
 *  - Country solo click again (on the currently-lone checked chip): restores
 *    all countries to checked.
 *  - Country shift+click: toggles just the clicked chip in/out of the
 *    current selection; if that empties the selection, all are restored.
 *  - Category chips: default all checked; unchecking one hides rows in that
 *    category (categoryOk = checkedCategories.has(category), so an empty
 *    category selection hides every row).
 *  - "N shown" (#filter-count) reflects only visible (non row-hidden) rows.
 *
 * Intentional differences introduced by the Phase 2 rewrite (D10), NOT
 * characterized as "must stay the same" here:
 *  - Chips start all UNSELECTED instead of all checked; "none selected"
 *    means "show everything" (today: none checked = show nothing).
 *  - Clicking a selected chip removes it (no separate solo-restore step).
 *  - An explicit "Clear filters" control replaces re-clicking the lone chip.
 *  - Selected-chip styling changes (filled surface-2 + purple border + ✓).
 */

'use strict';

function buildDom() {
    document.body.innerHTML = `
        <section id="results">
            <div id="filter-count-wrap">Showing <span id="filter-count">0</span> of <span id="filter-total">0</span></div>
            <div id="filter-categories">
                <label class="cat-scanning"><input type="checkbox" class="filter-category" value="scanning" checked><span class="chip-label">Scanning</span> <span class="chip-count">(0)</span></label>
                <label class="cat-cloud"><input type="checkbox" class="filter-category" value="cloud" checked><span class="chip-label">Cloud exit</span> <span class="chip-count">(0)</span></label>
            </div>
            <div id="filter-countries">
                <div class="filter-chips">
                    <label><input type="checkbox" class="filter-country" value="US" checked><span class="chip-label">US</span> <span class="chip-count">(0)</span></label>
                    <label><input type="checkbox" class="filter-country" value="CN" checked><span class="chip-label">CN</span> <span class="chip-count">(0)</span></label>
                    <label><input type="checkbox" class="filter-country" value="DE" checked><span class="chip-label">DE</span> <span class="chip-count">(0)</span></label>
                </div>
            </div>
            <table id="results-table"><tbody>
                <tr data-category="scanning" data-country="US"><td>1.1.1.1</td></tr>
                <tr data-category="cloud" data-country="US"><td>1.1.1.2</td></tr>
                <tr data-category="scanning" data-country="CN"><td>2.2.2.1</td></tr>
                <tr data-category="cloud" data-country="CN"><td>2.2.2.2</td></tr>
                <tr data-category="cloud" data-country="DE"><td>3.3.3.1</td></tr>
            </tbody></table>
        </section>
    `;
}

function countryChip(value) {
    return document.querySelector('.filter-country[value="' + value + '"]');
}

function categoryChip(value) {
    return document.querySelector('.filter-category[value="' + value + '"]');
}

function clickLabel(input) {
    var label = input.closest('label');
    label.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
}

function shiftClickLabel(input) {
    var label = input.closest('label');
    label.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, shiftKey: true }));
}

function visibleCount() {
    return document.getElementById('filter-count').textContent;
}

function shownRows() {
    return Array.from(document.querySelectorAll('#results-table tbody tr'))
        .filter(function (tr) { return !tr.classList.contains('row-hidden'); })
        .map(function (tr) { return tr.querySelector('td').textContent; });
}

describe('R14 characterization: today\'s chip behavior', () => {
    // ip2geo-app.js wires its filter logic via document-level delegated
    // listeners (addEventListener('click', ...) etc.) and a MutationObserver,
    // all attached once at require-time. Re-requiring it per test (even with
    // jest.resetModules) stacks a fresh set of listeners onto the same jsdom
    // `document` each time, so every later click fires N handlers at once —
    // that's why an early draft of this file saw doubled/cancelled toggles.
    // Requiring it exactly once and only resetting the DOM content per test
    // avoids that; the delegated listeners re-query the live DOM on every
    // event, so a fresh buildDom() per test is all they need.
    beforeAll(() => {
        buildDom();
        require('../../assets/js/ip2geo-app.js');
    });

    beforeEach(() => {
        buildDom();
        window.umami = { track: jest.fn() };
    });

    afterEach(() => {
        delete window.umami;
    });

    test('baseline: all chips checked by default shows every row', () => {
        expect(visibleCount()).toBe('5');
        expect(shownRows()).toEqual(['1.1.1.1', '1.1.1.2', '2.2.2.1', '2.2.2.2', '3.3.3.1']);
    });

    test('country solo click: shows only that country\'s rows and fires filter_country with no properties', () => {
        clickLabel(countryChip('US'));

        expect(countryChip('US').checked).toBe(true);
        expect(countryChip('CN').checked).toBe(false);
        expect(countryChip('DE').checked).toBe(false);
        expect(shownRows()).toEqual(['1.1.1.1', '1.1.1.2']);
        expect(visibleCount()).toBe('2');
        expect(window.umami.track).toHaveBeenCalledWith('filter_country');
        expect(window.umami.track.mock.calls[0].length).toBe(1);
    });

    test('country solo click again on the lone active chip restores all countries', () => {
        clickLabel(countryChip('US')); // solo US
        clickLabel(countryChip('US')); // click again -> restore

        expect(countryChip('US').checked).toBe(true);
        expect(countryChip('CN').checked).toBe(true);
        expect(countryChip('DE').checked).toBe(true);
        expect(visibleCount()).toBe('5');
    });

    test('country shift+click toggles just that chip into/out of the selection', () => {
        clickLabel(countryChip('US'));       // solo US
        shiftClickLabel(countryChip('CN'));  // add CN

        expect(countryChip('US').checked).toBe(true);
        expect(countryChip('CN').checked).toBe(true);
        expect(countryChip('DE').checked).toBe(false);
        expect(shownRows()).toEqual(['1.1.1.1', '1.1.1.2', '2.2.2.1', '2.2.2.2']);
    });

    test('shift+click emptying the selection restores all countries', () => {
        clickLabel(countryChip('US'));      // solo US
        shiftClickLabel(countryChip('US')); // toggle off -> nothing selected -> restore

        expect(countryChip('US').checked).toBe(true);
        expect(countryChip('CN').checked).toBe(true);
        expect(countryChip('DE').checked).toBe(true);
        expect(visibleCount()).toBe('5');
    });

    test('unchecking a category chip hides rows in that category', () => {
        var scanning = categoryChip('scanning');
        scanning.checked = false;
        scanning.dispatchEvent(new Event('change', { bubbles: true }));

        expect(shownRows()).toEqual(['1.1.1.2', '2.2.2.2', '3.3.3.1']);
        expect(visibleCount()).toBe('3');
    });

    test('unchecking every category chip hides every row (today: empty selection = nothing shown)', () => {
        [categoryChip('scanning'), categoryChip('cloud')].forEach(function (input) {
            input.checked = false;
            input.dispatchEvent(new Event('change', { bubbles: true }));
        });

        expect(shownRows()).toEqual([]);
        expect(visibleCount()).toBe('0');
    });

    test('country AND category filters combine as an intersection', () => {
        clickLabel(countryChip('CN')); // solo CN
        var scanning = categoryChip('scanning');
        scanning.checked = false;
        scanning.dispatchEvent(new Event('change', { bubbles: true }));

        // CN rows: 2.2.2.1 (scanning, now hidden) and 2.2.2.2 (cloud)
        expect(shownRows()).toEqual(['2.2.2.2']);
        expect(visibleCount()).toBe('1');
    });
});
