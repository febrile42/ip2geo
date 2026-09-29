/**
 * Jest test for D9 (IPG-134): toggling a category checkbox on the
 * server-rendered results table must fire `filter_category` with no
 * properties — the dimension only, never the category or its checked state.
 */

function buildDom() {
    document.body.innerHTML = `
        <section id="results">
            <div id="filter-categories">
                <label><input type="checkbox" class="filter-category" value="scanning" checked> Scanning</label>
                <label><input type="checkbox" class="filter-category" value="cloud" checked> Cloud</label>
            </div>
            <table id="results-table"><tbody>
                <tr data-category="scanning" data-country="US"><td>1.1.1.1</td></tr>
                <tr data-category="cloud" data-country="CN"><td>2.2.2.2</td></tr>
            </tbody></table>
        </section>
    `;
}

describe('filter_category analytics event', () => {
    beforeEach(() => {
        jest.resetModules();
        buildDom();
        window.umami = { track: jest.fn() };
    });

    afterEach(() => {
        delete window.umami;
    });

    test('fires with no properties when a category checkbox changes', () => {
        require('../../assets/js/ip2geo-app.js');

        var box = document.querySelector('.filter-category[value="scanning"]');
        box.checked = false;
        box.dispatchEvent(new Event('change', { bubbles: true }));

        var calls = window.umami.track.mock.calls.filter(c => c[0] === 'filter_category');
        expect(calls).toHaveLength(1);
        expect(calls[0]).toEqual(['filter_category']);
    });
});
