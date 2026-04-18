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

// Attach the format-toggle handler (mirrors production JS)
function attachToggleHandlers() {
  document.querySelectorAll('.format-toggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = document.getElementById(btn.dataset.target);
      var showing = target.hidden;
      target.hidden = !showing;
      btn.setAttribute('aria-expanded', showing ? 'true' : 'false');
      btn.innerHTML = (showing ? '&#9662; ' : '&#9656; ') + btn.dataset.label;
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
    buildFormatBlock();
    attachToggleHandlers();
  });

  test('block is hidden initially', () => {
    const block = document.getElementById('fmt-sh-ufw');
    expect(block.hidden).toBe(true);
  });

  test('first click reveals the block', () => {
    const btn = document.querySelector('.format-toggle');
    const block = document.getElementById('fmt-sh-ufw');
    btn.click();
    expect(block.hidden).toBe(false);
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
