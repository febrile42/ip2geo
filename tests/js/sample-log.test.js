/**
 * Jest tests for "Try a sample log" (D11 + R13 + R16) in assets/js/ip2geo-app.js:
 * fetches assets/sample-fail2ban.txt, appends the visitor's own IP as one
 * benign login line when available, fills the textarea, and sets a flag the
 * inline submit handler in index.php reads to send lookup_submit's
 * sample=true (D3 -- see index.php's window.__ip2geoSampleActive usage).
 *
 * Requires the real module (unlike the other tests/js/*.test.js files, which
 * mirror pure helpers) because the behavior under test — wiring fetch() to a
 * DOM element found by id — has no meaningful "pure function" to extract.
 * The DOM is built before require() so the module's top-level
 * getElementById() calls find the real elements.
 */

function buildDom() {
    document.body.innerHTML = `
        <textarea id="message"></textarea>
        <p class="sample-log-link"><a href="#" id="try-sample-log"
            data-sample-url="assets/sample-fail2ban.txt"
            data-visitor-ip="203.0.113.7">Try a sample log</a></p>
    `;
}

function flushMicrotasks() {
    return new Promise((resolve) => setTimeout(resolve, 0));
}

describe('Try a sample log', () => {
    let originalFetch;

    beforeEach(() => {
        jest.resetModules();
        buildDom();
        originalFetch = global.fetch;
        window.umami = { track: jest.fn() };
        window.__ip2geoSampleActive = undefined;
    });

    afterEach(() => {
        global.fetch = originalFetch;
        delete window.umami;
    });

    test('fills the textarea with the fetched sample text', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('Sep 22 00:12:16 demo sshd[1]: Failed password from 192.241.221.224 port 1 ssh2\n'),
        });

        require('../../assets/js/ip2geo-app.js');

        document.getElementById('try-sample-log').dispatchEvent(
            new MouseEvent('click', { bubbles: true, cancelable: true })
        );
        await flushMicrotasks();
        await flushMicrotasks();

        const textarea = document.getElementById('message');
        expect(textarea.value).toContain('192.241.221.224');
    });

    test('appends one benign line with the visitor IP, marked for the (you) row', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('Sep 22 00:12:16 demo sshd[1]: Failed password from 192.241.221.224 port 1 ssh2\n'),
        });

        require('../../assets/js/ip2geo-app.js');

        document.getElementById('try-sample-log').dispatchEvent(
            new MouseEvent('click', { bubbles: true, cancelable: true })
        );
        await flushMicrotasks();
        await flushMicrotasks();

        const textarea = document.getElementById('message');
        expect(textarea.value).toContain('Accepted publickey for analyst from 203.0.113.7 port 52144 ssh2');
    });

    test('omits the visitor line when data-visitor-ip is empty', async () => {
        document.getElementById('try-sample-log').removeAttribute('data-visitor-ip');
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('Sep 22 00:12:16 demo sshd[1]: Failed password from 192.241.221.224 port 1 ssh2\n'),
        });

        require('../../assets/js/ip2geo-app.js');

        document.getElementById('try-sample-log').dispatchEvent(
            new MouseEvent('click', { bubbles: true, cancelable: true })
        );
        await flushMicrotasks();
        await flushMicrotasks();

        const textarea = document.getElementById('message');
        expect(textarea.value).not.toContain('Accepted publickey');
    });

    test('sets window.__ip2geoSampleActive after loading the sample', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('Sep 22 00:12:16 demo sshd[1]: Failed password from 192.241.221.224 port 1 ssh2\n'),
        });

        require('../../assets/js/ip2geo-app.js');

        document.getElementById('try-sample-log').dispatchEvent(
            new MouseEvent('click', { bubbles: true, cancelable: true })
        );
        await flushMicrotasks();
        await flushMicrotasks();

        expect(window.__ip2geoSampleActive).toBe(true);
    });

    test('editing the textarea afterward clears the sample flag', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve('Sep 22 00:12:16 demo sshd[1]: Failed password from 192.241.221.224 port 1 ssh2\n'),
        });

        require('../../assets/js/ip2geo-app.js');

        document.getElementById('try-sample-log').dispatchEvent(
            new MouseEvent('click', { bubbles: true, cancelable: true })
        );
        await flushMicrotasks();
        await flushMicrotasks();
        expect(window.__ip2geoSampleActive).toBe(true);

        const textarea = document.getElementById('message');
        textarea.value += ' edited by hand';
        textarea.dispatchEvent(new Event('input', { bubbles: true }));

        expect(window.__ip2geoSampleActive).toBe(false);
    });

    test('a failed fetch leaves the textarea untouched', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('network down'));

        require('../../assets/js/ip2geo-app.js');

        const textarea = document.getElementById('message');
        textarea.value = 'whatever was already there';

        document.getElementById('try-sample-log').dispatchEvent(
            new MouseEvent('click', { bubbles: true, cancelable: true })
        );
        await flushMicrotasks();
        await flushMicrotasks();

        expect(textarea.value).toBe('whatever was already there');
    });
});
