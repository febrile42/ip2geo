/**
 * Tap-to-explain popover for DROP labels (assets/js/abbr-popover.js).
 * Title tooltips never appear on touch screens; tapping must show the text.
 */
const Pop = require('../../assets/js/abbr-popover.js');

const TIP = "Spamhaus DROP (Don't Route Or Peer): test text.";

function setup() {
  document.body.innerHTML = `
    <table><tr><td><abbr class="drop-tag" title="${TIP}">DROP</abbr></td></tr></table>
    <p class="lookup-summary-drop">14 in <abbr title="${TIP}">Spamhaus DROP</abbr> netblocks</p>
    <button id="elsewhere">x</button>`;
  return Pop.install(document);
}

describe('abbr popover', () => {
  let api;
  beforeEach(() => { api = setup(); });
  afterEach(() => { api.close(); });

  test('tapping a DROP tag opens a popover with its title text', () => {
    document.querySelector('abbr.drop-tag').click();
    const pop = document.getElementById('abbr-pop');
    expect(pop).not.toBeNull();
    expect(pop.textContent).toBe(TIP);
    expect(pop.getAttribute('role')).toBe('tooltip');
    expect(document.querySelector('abbr.drop-tag').getAttribute('aria-describedby')).toBe('abbr-pop');
  });

  test('tapping the same tag again closes it', () => {
    const a = document.querySelector('abbr.drop-tag');
    a.click(); a.click();
    expect(document.getElementById('abbr-pop')).toBeNull();
    expect(a.getAttribute('aria-expanded')).toBe('false');
  });

  test('tapping elsewhere closes it', () => {
    document.querySelector('abbr.drop-tag').click();
    document.getElementById('elsewhere').click();
    expect(document.getElementById('abbr-pop')).toBeNull();
  });

  test('the summary line abbr opens it too, and only one popover exists at a time', () => {
    document.querySelector('abbr.drop-tag').click();
    document.querySelector('.lookup-summary-drop abbr').click();
    expect(document.querySelectorAll('#abbr-pop').length).toBe(1);
  });

  test('labels are focusable, Enter opens and Escape closes', () => {
    const a = document.querySelector('abbr.drop-tag');
    expect(a.getAttribute('tabindex')).toBe('0');
    a.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(document.getElementById('abbr-pop')).not.toBeNull();
    a.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(document.getElementById('abbr-pop')).toBeNull();
  });
});
