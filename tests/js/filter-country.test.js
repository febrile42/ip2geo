/**
 * Jest test for R9/D8: clicking a country filter chip must fire
 * `filter_country` with no properties — the country code is paste-derived
 * data and, as of v5, no longer goes to analytics (only that the filter was
 * used does).
 */

function buildDom() {
    document.body.innerHTML = `
        <section id="results">
            <div id="filter-countries">
                <div class="filter-chips">
                    <label><input type="checkbox" class="filter-country" value="US" checked><span class="chip-label">US</span> <span class="chip-count">(3)</span></label>
                    <label><input type="checkbox" class="filter-country" value="CN" checked><span class="chip-label">CN</span> <span class="chip-count">(2)</span></label>
                </div>
            </div>
            <table id="results-table"><tbody>
                <tr data-category="scanning" data-country="US"><td>1.1.1.1</td></tr>
                <tr data-category="scanning" data-country="CN"><td>2.2.2.2</td></tr>
            </tbody></table>
        </section>
    `;
}

describe('filter_country analytics event', () => {
    beforeEach(() => {
        jest.resetModules();
        buildDom();
        window.umami = { track: jest.fn() };
    });

    afterEach(() => {
        delete window.umami;
    });

    test('fires with no properties on an exclusive-select click', () => {
        require('../../assets/js/ip2geo-app.js');

        var label = document.querySelector('#filter-countries label');
        label.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

        expect(window.umami.track).toHaveBeenCalledWith('filter_country');
        // Explicitly not called with a country-carrying payload.
        expect(window.umami.track).not.toHaveBeenCalledWith('filter_country', expect.anything());
    });
});
