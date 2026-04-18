/**
 * Jest tests for the copy-button + format-toggle JS in report.php.
 *
 * The production handlers attach via querySelectorAll after DOMContentLoaded.
 * We build the relevant DOM nodes, attach the handlers manually, and fire events.
 */

// ── DOM builder ───────────────────────────────────────────────────────────────

function buildFormatBlock(fmt = 'sh-ufw', scriptText = 'ufw deny from 1.2.3.4 to any') {
  document.body.innerHTML = `
    <div class="format-entry">
      <button class="format-toggle button small"
              data-target="fmt-${fmt}"
              data-label="block-ufw.sh"
              aria-expanded="false">&#9656; block-ufw.sh</button>
      <div id="fmt-${fmt}" class="format-block" hidden>
        <div class="format-actions">
          <button class="copy-btn button small">&#128203; Copy</button>
          <a href="/report.php?token=abc&format=${fmt}" class="button small">&#8595; Download</a>
        </div>
        <pre class="block-script-preview"><code>${scriptText}</code></pre>
      </div>
    </div>
  `;
}

// Build two format blocks inside a shared panel (for accordion tests)
function buildTwoFormatBlocks() {
  document.body.innerHTML = `
    <div class="block-rules-panel">
      <div class="format-entry">
        <button class="format-toggle button small"
                data-target="fmt-sh-ufw"
                data-label="block-ufw.sh"
                aria-expanded="false">&#9656; block-ufw.sh</button>
        <div id="fmt-sh-ufw" class="format-block" hidden>
          <div class="format-actions">
            <button class="copy-btn button small">&#128203; Copy</button>
          </div>
          <pre class="block-script-preview"><code>ufw deny from 1.2.3.4 to any</code></pre>
        </div>
      </div>
      <div class="format-entry">
        <button class="format-toggle button small"
                data-target="fmt-sh-iptables"
                data-label="block-iptables.sh"
                aria-expanded="false">&#9656; block-iptables.sh</button>
        <div id="fmt-sh-iptables" class="format-block" hidden>
          <div class="format-actions">
            <button class="copy-btn button small">&#128203; Copy</button>
          </div>
          <pre class="block-script-preview"><code>iptables -A INPUT -s 1.2.3.4 -j DROP</code></pre>
        </div>
      </div>
    </div>
  `;
}

// Attach the format-toggle handler — accordion: one open at a time per panel
function attachToggleHandlers() {
  document.querySelectorAll('.format-toggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = document.getElementById(btn.dataset.target);
      var opening = target.hidden;
      var panel = btn.closest('.block-rules-panel') || btn.closest('.format-entry').parentElement;
      panel.querySelectorAll('.format-toggle').forEach(function (other) {
        var otherTarget = document.getElementById(other.dataset.target);
        otherTarget.hidden = true;
        other.setAttribute('aria-expanded', 'false');
        other.innerHTML = '&#9656; ' + other.dataset.label;
      });
      if (opening) {
        target.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
        btn.innerHTML = '&#9662; ' + btn.dataset.label;
      }
    });
  });
}

// Attach the copy-btn handler (mirrors production JS)
function attachCopyHandlers() {
  document.querySelectorAll('.copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var pre = btn.closest('.format-block').querySelector('pre');
      var text = pre.textContent;
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = 'Copied!';
          setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
        });
      } else {
        var sel = window.getSelection();
        var range = document.createRange();
        range.selectNodeContents(pre);
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand('copy');
        sel.removeAllRanges();
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
      }
    });
  });
}

// ── Format toggle tests ───────────────────────────────────────────────────────

describe('format-toggle', () => {
  beforeEach(() => {
    // Single block wrapped in a panel so accordion scoping works
    document.body.innerHTML = `
      <div class="block-rules-panel">
        <div class="format-entry">
          <button class="format-toggle button small"
                  data-target="fmt-sh-ufw"
                  data-label="block-ufw.sh"
                  aria-expanded="false">&#9656; block-ufw.sh</button>
          <div id="fmt-sh-ufw" class="format-block" hidden>
            <div class="format-actions">
              <button class="copy-btn button small">&#128203; Copy</button>
            </div>
            <pre class="block-script-preview"><code>ufw deny from 1.2.3.4 to any</code></pre>
          </div>
        </div>
      </div>`;
    attachToggleHandlers();
  });

  test('block is hidden initially', () => {
    expect(document.getElementById('fmt-sh-ufw').hidden).toBe(true);
  });

  test('first click reveals the block', () => {
    document.querySelector('.format-toggle').click();
    expect(document.getElementById('fmt-sh-ufw').hidden).toBe(false);
  });

  test('sets aria-expanded=true when opened', () => {
    const btn = document.querySelector('.format-toggle');
    btn.click();
    expect(btn.getAttribute('aria-expanded')).toBe('true');
  });

  test('second click hides the block again', () => {
    const btn = document.querySelector('.format-toggle');
    const block = document.getElementById('fmt-sh-ufw');
    btn.click();
    btn.click();
    expect(block.hidden).toBe(true);
    expect(btn.getAttribute('aria-expanded')).toBe('false');
  });
});

describe('format-toggle: accordion', () => {
  beforeEach(() => {
    buildTwoFormatBlocks();
    attachToggleHandlers();
  });

  test('opening second format closes first', () => {
    const [btn1, btn2] = document.querySelectorAll('.format-toggle');
    btn1.click();
    expect(document.getElementById('fmt-sh-ufw').hidden).toBe(false);
    btn2.click();
    expect(document.getElementById('fmt-sh-ufw').hidden).toBe(true);
    expect(document.getElementById('fmt-sh-iptables').hidden).toBe(false);
  });

  test('clicking open format closes it (toggle off)', () => {
    const btn1 = document.querySelector('.format-toggle');
    btn1.click();
    btn1.click();
    expect(document.getElementById('fmt-sh-ufw').hidden).toBe(true);
    expect(btn1.getAttribute('aria-expanded')).toBe('false');
  });
});

// ── Copy button tests — clipboard API path ────────────────────────────────────

describe('copy-btn: clipboard API', () => {
  let writeTextMock;

  beforeEach(() => {
    buildFormatBlock('sh-ufw', 'ufw deny from 1.2.3.4 to any');
    // Reveal the block so copy-btn is reachable
    document.getElementById('fmt-sh-ufw').hidden = false;

    writeTextMock = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: writeTextMock },
      configurable: true,
      writable: true,
    });
    Object.defineProperty(window, 'isSecureContext', {
      value: true,
      configurable: true,
      writable: true,
    });

    attachCopyHandlers();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test('calls clipboard.writeText with pre textContent', async () => {
    const btn = document.querySelector('.copy-btn');
    btn.click();
    await Promise.resolve(); // flush microtask
    expect(writeTextMock).toHaveBeenCalledWith('ufw deny from 1.2.3.4 to any');
  });

  test('button text becomes Copied! after write', async () => {
    const btn = document.querySelector('.copy-btn');
    btn.click();
    await Promise.resolve();
    expect(btn.textContent).toBe('Copied!');
  });

  test('button text resets to Copy after 2s', async () => {
    const btn = document.querySelector('.copy-btn');
    btn.click();
    await Promise.resolve();
    jest.advanceTimersByTime(2000);
    expect(btn.textContent).toBe('Copy');
  });
});

// ── Copy button tests — execCommand fallback ──────────────────────────────────

describe('copy-btn: execCommand fallback', () => {
  let execCommandSpy;

  beforeEach(() => {
    buildFormatBlock('sh-ufw', 'ufw deny from 5.6.7.8 to any');
    document.getElementById('fmt-sh-ufw').hidden = false;

    // Remove clipboard API to force fallback
    Object.defineProperty(navigator, 'clipboard', {
      value: undefined,
      configurable: true,
      writable: true,
    });
    Object.defineProperty(window, 'isSecureContext', {
      value: false,
      configurable: true,
      writable: true,
    });

    execCommandSpy = jest.fn().mockReturnValue(true);
    document.execCommand = execCommandSpy;
    attachCopyHandlers();
    jest.useFakeTimers();
  });

  afterEach(() => {
    delete document.execCommand;
    jest.useRealTimers();
  });

  test('calls execCommand copy', () => {
    document.querySelector('.copy-btn').click();
    expect(execCommandSpy).toHaveBeenCalledWith('copy');
  });

  test('button text becomes Copied! in fallback path', () => {
    const btn = document.querySelector('.copy-btn');
    btn.click();
    expect(btn.textContent).toBe('Copied!');
  });

  test('button text resets after 2s in fallback path', () => {
    const btn = document.querySelector('.copy-btn');
    btn.click();
    jest.advanceTimersByTime(2000);
    expect(btn.textContent).toBe('Copy');
  });
});
