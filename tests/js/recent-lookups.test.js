/**
 * Jest tests for the recent-lookups opt-in localStorage feature in
 * assets/js/ip2geo-app.js.
 *
 * Mirrors the dwell.test.js / copy-btn.test.js pattern: extract logic into
 * pure functions, attach handlers in jsdom, mock browser APIs (localStorage,
 * umami, custom events).
 */

// ── Constants (match production) ──────────────────────────────────────────────

const OPTIN_KEY = 'rl_optin';
const LIST_KEY  = 'rl_list';
const MAX_ENTRIES = 20;
const IPS_PER_ENTRY_CAP = 10000;
const TOAST_TIMEOUT_MS = 6000;

// ── Pure helpers — mirror of production logic in ip2geo-app.js ────────────────

function isStorageAvailable() {
    try {
        var t = '_rl_test';
        window.localStorage.setItem(t, '1');
        window.localStorage.removeItem(t);
        return true;
    } catch (_) {
        return false;
    }
}

function loadOptInState() {
    try { return window.localStorage.getItem(OPTIN_KEY) === '1'; }
    catch (_) { return false; }
}

function saveOptInState(value) {
    try {
        if (value) window.localStorage.setItem(OPTIN_KEY, '1');
        else       window.localStorage.removeItem(OPTIN_KEY);
    } catch (_) {}
}

function loadList() {
    try {
        var raw = window.localStorage.getItem(LIST_KEY);
        if (raw === null) return [];
        var parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
        return [];
    }
}

function saveList(items) {
    var capped = items.length > MAX_ENTRIES
        ? items.slice(items.length - MAX_ENTRIES)
        : items;
    while (capped.length > 0) {
        try {
            window.localStorage.setItem(LIST_KEY, JSON.stringify(capped));
            return true;
        } catch (_) {
            capped = capped.slice(1);
        }
    }
    return false;
}

function clearList() {
    try { window.localStorage.removeItem(LIST_KEY); } catch (_) {}
}

function buildEntry(ips, count, nowMs) {
    var safeIps = (ips || []).slice(0, IPS_PER_ENTRY_CAP);
    var safeCount = (typeof count === 'number' && count >= 0) ? count : safeIps.length;
    return { ips: safeIps, count: safeCount, ts: nowMs };
}

function fingerprintIps(ips) {
    return (ips || []).join('\n');
}

function appendLookup(ips, count) {
    if (!loadOptInState()) return;
    var list = loadList();
    var entry = buildEntry(ips, count, Date.now());
    var fp = fingerprintIps(entry.ips);
    var dupeIdx = -1;
    for (var i = list.length - 1; i >= 0; i--) {
        if (fingerprintIps(list[i].ips) === fp) { dupeIdx = i; break; }
    }
    if (dupeIdx >= 0) list.splice(dupeIdx, 1);
    list.push(entry);
    saveList(list);
}

function relativeTime(ts, nowMs) {
    var diffSecs = Math.floor((nowMs - ts) / 1000);
    if (diffSecs < 60)    return diffSecs <= 1 ? 'just now' : diffSecs + ' sec ago';
    var diffMins = Math.floor(diffSecs / 60);
    if (diffMins < 60)    return diffMins === 1 ? '1 min ago' : diffMins + ' min ago';
    var diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24)   return diffHours === 1 ? '1 hr ago' : diffHours + ' hr ago';
    var diffDays = Math.floor(diffHours / 24);
    return diffDays === 1 ? '1 day ago' : diffDays + ' days ago';
}

// ── Setup helpers ─────────────────────────────────────────────────────────────

beforeEach(() => {
    window.localStorage.clear();
    document.body.innerHTML = '';
});

// ── isStorageAvailable ────────────────────────────────────────────────────────

describe('isStorageAvailable', () => {
    test('returns true when localStorage works', () => {
        expect(isStorageAvailable()).toBe(true);
    });

    test('returns false when setItem throws', () => {
        const spy = jest.spyOn(Storage.prototype, 'setItem')
            .mockImplementation(() => { throw new Error('quota'); });
        expect(isStorageAvailable()).toBe(false);
        spy.mockRestore();
    });
});

// ── loadOptInState ────────────────────────────────────────────────────────────

describe('loadOptInState', () => {
    test('returns false on missing key', () => {
        expect(loadOptInState()).toBe(false);
    });

    test('returns true on key value "1"', () => {
        window.localStorage.setItem(OPTIN_KEY, '1');
        expect(loadOptInState()).toBe(true);
    });

    test('returns false on other value', () => {
        window.localStorage.setItem(OPTIN_KEY, 'true');
        expect(loadOptInState()).toBe(false);
    });
});

// ── saveOptInState ────────────────────────────────────────────────────────────

describe('saveOptInState', () => {
    test('true sets key to "1"', () => {
        saveOptInState(true);
        expect(window.localStorage.getItem(OPTIN_KEY)).toBe('1');
    });

    test('false removes the key', () => {
        window.localStorage.setItem(OPTIN_KEY, '1');
        saveOptInState(false);
        expect(window.localStorage.getItem(OPTIN_KEY)).toBeNull();
    });
});

// ── loadList ──────────────────────────────────────────────────────────────────

describe('loadList', () => {
    test('returns empty array on missing key', () => {
        expect(loadList()).toEqual([]);
    });

    test('returns empty array on corrupt JSON', () => {
        window.localStorage.setItem(LIST_KEY, '{not valid json');
        expect(loadList()).toEqual([]);
    });

    test('returns parsed array on valid JSON', () => {
        window.localStorage.setItem(LIST_KEY, JSON.stringify([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]));
        const list = loadList();
        expect(list).toHaveLength(1);
        expect(list[0].ips[0]).toBe('1.1.1.1');
    });

    test('returns empty array when stored value is not an array', () => {
        window.localStorage.setItem(LIST_KEY, JSON.stringify({ not: 'an array' }));
        expect(loadList()).toEqual([]);
    });
});

// ── saveList ──────────────────────────────────────────────────────────────────

describe('saveList', () => {
    test('writes array under cap to localStorage', () => {
        const items = [{ ips: ['1.1.1.1'], count: 1, ts: 100 }];
        const ok = saveList(items);
        expect(ok).toBe(true);
        expect(JSON.parse(window.localStorage.getItem(LIST_KEY))).toHaveLength(1);
    });

    test('truncates to last MAX_ENTRIES when over cap (FIFO eviction of oldest)', () => {
        const items = [];
        for (let i = 0; i < MAX_ENTRIES + 5; i++) {
            items.push({ ips: [], count: i, ts: i });
        }
        saveList(items);
        const stored = JSON.parse(window.localStorage.getItem(LIST_KEY));
        expect(stored).toHaveLength(MAX_ENTRIES);
        // Oldest 5 should be gone; newest preserved
        expect(stored[0].count).toBe(5);
        expect(stored[stored.length - 1].count).toBe(MAX_ENTRIES + 4);
    });

    test('on QuotaExceeded, drops oldest and retries once', () => {
        const items = [
            { ips: [], count: 1, ts: 1 },
            { ips: [], count: 2, ts: 2 },
        ];
        const realSetItem = Storage.prototype.setItem;
        let callCount = 0;
        const spy = jest.spyOn(Storage.prototype, 'setItem')
            .mockImplementation(function (key, value) {
                callCount++;
                if (callCount === 1) throw new Error('quota');
                return realSetItem.call(this, key, value);
            });
        const ok = saveList(items);
        expect(ok).toBe(true);
        expect(callCount).toBe(2); // failed once, retried with one fewer
        const stored = JSON.parse(window.localStorage.getItem(LIST_KEY));
        expect(stored).toHaveLength(1);
        expect(stored[0].count).toBe(2); // newer entry kept
        spy.mockRestore();
    });

    test('on persistent QuotaExceeded, drops oldest iteratively until it fits', () => {
        const items = [
            { ips: [], count: 1, ts: 1 },
            { ips: [], count: 2, ts: 2 },
            { ips: [], count: 3, ts: 3 },
            { ips: [], count: 4, ts: 4 },
        ];
        const realSetItem = Storage.prototype.setItem;
        let callCount = 0;
        const spy = jest.spyOn(Storage.prototype, 'setItem')
            .mockImplementation(function (key, value) {
                callCount++;
                // Fail until only 1 entry remains
                if (callCount < 4) throw new Error('quota');
                return realSetItem.call(this, key, value);
            });
        const ok = saveList(items);
        expect(ok).toBe(true);
        expect(callCount).toBe(4); // 4,3,2 throw; 1-entry write succeeds
        const stored = JSON.parse(window.localStorage.getItem(LIST_KEY));
        expect(stored).toHaveLength(1);
        expect(stored[0].count).toBe(4); // newest preserved, oldest 3 evicted
        spy.mockRestore();
    });

    test('returns false when single entry exceeds quota even alone', () => {
        const items = [{ ips: [], count: 1, ts: 1 }];
        const spy = jest.spyOn(Storage.prototype, 'setItem')
            .mockImplementation(() => { throw new Error('quota'); });
        const ok = saveList(items);
        expect(ok).toBe(false); // can't fit, give up — never block lookup flow
        spy.mockRestore();
    });

    test('on persistent QuotaExceeded, gives up silently', () => {
        const items = [
            { ips: [], count: 1, ts: 1 },
            { ips: [], count: 2, ts: 2 },
        ];
        const spy = jest.spyOn(Storage.prototype, 'setItem')
            .mockImplementation(() => { throw new Error('quota'); });
        const ok = saveList(items);
        expect(ok).toBe(false);
        spy.mockRestore();
    });
});

// ── buildEntry ────────────────────────────────────────────────────────────────

describe('buildEntry', () => {
    test('caps stored ips to IPS_PER_ENTRY_CAP', () => {
        const overCap = IPS_PER_ENTRY_CAP + 5;
        const ips = [];
        for (let i = 0; i < overCap; i++) ips.push('10.0.0.' + (i % 256));
        const entry = buildEntry(ips, overCap, 12345);
        expect(entry.ips).toHaveLength(IPS_PER_ENTRY_CAP);
        expect(entry.count).toBe(overCap);
        expect(entry.ts).toBe(12345);
    });

    test('regression: 10,000 IPs round-trip without truncation (FINDING: silent slice(0,50) on save)', () => {
        // Bug: large lookups labeled "10,000 IPs" but only 50 stored.
        // After fix: cap matches site input max so a 10K lookup is preserved verbatim.
        const ips = [];
        for (let i = 0; i < 10000; i++) ips.push('10.' + ((i >> 16) & 255) + '.' + ((i >> 8) & 255) + '.' + (i & 255));
        const entry = buildEntry(ips, ips.length, 1);
        expect(entry.ips).toHaveLength(10000);
        expect(entry.count).toBe(10000);
        expect(entry.ips[0]).toBe(ips[0]);
        expect(entry.ips[9999]).toBe(ips[9999]);
    });

    test('uses ips length when count missing', () => {
        const entry = buildEntry(['1.1.1.1', '2.2.2.2'], undefined, 1);
        expect(entry.count).toBe(2);
    });

    test('handles null/undefined ips', () => {
        const entry = buildEntry(null, 0, 1);
        expect(entry.ips).toEqual([]);
        expect(entry.count).toBe(0);
    });
});

// ── appendLookup ──────────────────────────────────────────────────────────────

describe('appendLookup', () => {
    test('opt-in OFF: noop, no list write', () => {
        appendLookup(['1.1.1.1'], 1);
        expect(window.localStorage.getItem(LIST_KEY)).toBeNull();
    });

    test('opt-in ON: appends entry to list', () => {
        saveOptInState(true);
        appendLookup(['1.1.1.1'], 1);
        const list = loadList();
        expect(list).toHaveLength(1);
        expect(list[0].ips).toEqual(['1.1.1.1']);
        expect(list[0].count).toBe(1);
    });

    test('opt-in ON: multiple appends preserve order', () => {
        saveOptInState(true);
        appendLookup(['1.1.1.1'], 1);
        appendLookup(['2.2.2.2', '3.3.3.3'], 2);
        const list = loadList();
        expect(list).toHaveLength(2);
        expect(list[0].count).toBe(1);
        expect(list[1].count).toBe(2);
    });

    test('dedupe: identical IP list collapses onto existing entry, ts refreshed', () => {
        saveOptInState(true);
        const realNow = Date.now;
        let now = 1000;
        Date.now = () => now;
        try {
            appendLookup(['1.1.1.1', '2.2.2.2'], 2);
            now = 5000;
            appendLookup(['3.3.3.3'], 1); // distinct entry between dupes
            now = 9000;
            appendLookup(['1.1.1.1', '2.2.2.2'], 2); // dupe of first
            const list = loadList();
            expect(list).toHaveLength(2); // 3 appends, 1 dedup'd
            // Newest entry is the promoted dupe
            expect(list[list.length - 1].ips).toEqual(['1.1.1.1', '2.2.2.2']);
            expect(list[list.length - 1].ts).toBe(9000);
            // Distinct entry stays in place
            expect(list[0].ips).toEqual(['3.3.3.3']);
        } finally {
            Date.now = realNow;
        }
    });

    test('dedupe: different order = different entry (not deduplicated)', () => {
        saveOptInState(true);
        appendLookup(['1.1.1.1', '2.2.2.2'], 2);
        appendLookup(['2.2.2.2', '1.1.1.1'], 2); // same IPs, different order
        const list = loadList();
        expect(list).toHaveLength(2);
    });

    test('dedupe: edited list (one IP added) = different entry', () => {
        saveOptInState(true);
        appendLookup(['1.1.1.1', '2.2.2.2'], 2);
        appendLookup(['1.1.1.1', '2.2.2.2', '3.3.3.3'], 3);
        const list = loadList();
        expect(list).toHaveLength(2);
    });
});

// ── relativeTime ──────────────────────────────────────────────────────────────

describe('relativeTime', () => {
    test('just now for <2 seconds', () => {
        expect(relativeTime(1000, 1000)).toBe('just now');
        expect(relativeTime(1000, 2000)).toBe('just now');
    });

    test('seconds for <60s', () => {
        expect(relativeTime(0, 30000)).toBe('30 sec ago');
    });

    test('minutes for <60min', () => {
        expect(relativeTime(0, 60 * 1000)).toBe('1 min ago');
        expect(relativeTime(0, 5 * 60 * 1000)).toBe('5 min ago');
    });

    test('hours for <24h', () => {
        expect(relativeTime(0, 60 * 60 * 1000)).toBe('1 hr ago');
        expect(relativeTime(0, 5 * 60 * 60 * 1000)).toBe('5 hr ago');
    });

    test('days for >=24h', () => {
        expect(relativeTime(0, 24 * 60 * 60 * 1000)).toBe('1 day ago');
        expect(relativeTime(0, 3 * 24 * 60 * 60 * 1000)).toBe('3 days ago');
    });
});

// ── DOM integration tests ────────────────────────────────────────────────────

function buildDOM() {
    document.body.innerHTML = `
        <div id="recent-lookups" hidden>
            <div id="recent-lookups-header">
                <h3>Recent lookups</h3>
                <button type="button" id="recent-lookups-clear" class="button small">Clear</button>
            </div>
            <ul id="recent-lookups-list"></ul>
        </div>
        <textarea id="message"></textarea>
        <label id="rl-optin-row" class="opt-in-toggle" hidden>
            <input type="checkbox" id="rl-optin">
        </label>
        <div id="rl-toast" role="status" aria-live="polite" hidden>
            <span id="rl-toast-msg"></span>
            <button type="button" id="rl-toast-undo">Undo</button>
        </div>
    `;
}

// Mirror of the production renderList() + handlers, attached to the test DOM
function attachHandlers() {
    let toastTimer = null;
    let pendingUndo = null;

    function renderList() {
        const widget = document.getElementById('recent-lookups');
        const listEl = document.getElementById('recent-lookups-list');
        if (!widget || !listEl) return;
        const optIn = loadOptInState();
        const items = loadList();
        if (!optIn || !items.length) {
            widget.hidden = true;
            listEl.innerHTML = '';
            return;
        }
        widget.hidden = false;
        listEl.innerHTML = '';
        const now = Date.now();
        items.slice().reverse().forEach((entry, revIdx) => {
            const origIdx = items.length - 1 - revIdx;
            const li = document.createElement('li');
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'recent-lookup-item';
            btn.dataset.idx = String(origIdx);
            btn.textContent = `${entry.count} IPs`;
            li.appendChild(btn);
            listEl.appendChild(li);
        });
    }

    function showToast(message, undoFn) {
        const toast = document.getElementById('rl-toast');
        const msgEl = document.getElementById('rl-toast-msg');
        if (!toast || !msgEl) return;
        if (toastTimer) {
            clearTimeout(toastTimer);
            toastTimer = null;
            pendingUndo = null;
        }
        msgEl.textContent = message;
        pendingUndo = undoFn;
        toast.hidden = false;
        toast.classList.add('rl-toast-visible');
        toastTimer = setTimeout(() => hideToast(false), TOAST_TIMEOUT_MS);
    }

    function hideToast(viaUndo) {
        const toast = document.getElementById('rl-toast');
        if (!toast) return;
        if (viaUndo && typeof pendingUndo === 'function') {
            try { pendingUndo(); } catch (_) {}
        }
        pendingUndo = null;
        if (toastTimer) {
            clearTimeout(toastTimer);
            toastTimer = null;
        }
        toast.classList.remove('rl-toast-visible');
        toast.hidden = true;
    }

    function handleToggleChange(event) {
        const checked = event.target.checked;
        if (checked) {
            saveOptInState(true);
            renderList();
            return;
        }
        const listSnapshot = loadList();
        if (!listSnapshot.length) {
            saveOptInState(false);
            renderList();
            return;
        }
        saveOptInState(false);
        clearList();
        renderList();
        showToast(`Cleared ${listSnapshot.length} lookups.`, () => {
            saveOptInState(true);
            saveList(listSnapshot);
            renderList();
            const optInEl = document.getElementById('rl-optin');
            if (optInEl) optInEl.checked = true;
        });
    }

    function handleClearClick() {
        const listSnapshot = loadList();
        if (!listSnapshot.length) return;
        clearList();
        renderList();
        showToast(`Cleared ${listSnapshot.length} lookups.`, () => {
            saveList(listSnapshot);
            renderList();
        });
    }

    function handleListClick(event) {
        const btn = event.target.closest && event.target.closest('.recent-lookup-item');
        if (!btn) return;
        const idx = parseInt(btn.dataset.idx, 10);
        if (isNaN(idx)) return;
        const items = loadList();
        const entry = items[idx];
        if (!entry) return;
        const textarea = document.getElementById('message');
        if (!textarea) return;
        textarea.value = entry.ips.join('\n');
    }

    function handleLookupSubmit(event) {
        const detail = event.detail || {};
        appendLookup(detail.ips, detail.count);
        renderList();
    }

    const row = document.getElementById('rl-optin-row');
    const optInEl = document.getElementById('rl-optin');
    if (row && optInEl) {
        if (isStorageAvailable()) row.hidden = false;
        optInEl.checked = loadOptInState();
        optInEl.addEventListener('change', handleToggleChange);
    }
    const clearBtn = document.getElementById('recent-lookups-clear');
    if (clearBtn) clearBtn.addEventListener('click', handleClearClick);
    const listEl = document.getElementById('recent-lookups-list');
    if (listEl) listEl.addEventListener('click', handleListClick);
    const undoBtn = document.getElementById('rl-toast-undo');
    if (undoBtn) undoBtn.addEventListener('click', () => hideToast(true));
    document.addEventListener('ip2geo:lookup_submit', handleLookupSubmit);

    renderList();
    return {
        renderList,
        showToast,
        hideToast,
        detach: () => {
            document.removeEventListener('ip2geo:lookup_submit', handleLookupSubmit);
        }
    };
}

// ── Toggle interaction tests ─────────────────────────────────────────────────

describe('handleToggleChange', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        __handlers = attachHandlers();
        jest.useFakeTimers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
        jest.useRealTimers();
    });

    test('checking the toggle saves opt-in and reveals widget when nonempty', () => {
        const cb = document.getElementById('rl-optin');
        cb.checked = true;
        cb.dispatchEvent(new Event('change'));
        expect(loadOptInState()).toBe(true);
    });

    test('unchecking with empty list: silent off, no toast', () => {
        saveOptInState(true);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        expect(loadOptInState()).toBe(false);
        expect(document.getElementById('rl-toast').hidden).toBe(true);
    });

    test('unchecking with nonempty list: clears + shows toast', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        expect(loadList()).toEqual([]);
        expect(document.getElementById('rl-toast').hidden).toBe(false);
    });
});

// ── Toast with undo ──────────────────────────────────────────────────────────

describe('toast with undo', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        __handlers = attachHandlers();
        jest.useFakeTimers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
        jest.useRealTimers();
    });

    test('appears with message and Undo button when uncheck triggers it', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        const toast = document.getElementById('rl-toast');
        expect(toast.hidden).toBe(false);
        expect(toast.classList.contains('rl-toast-visible')).toBe(true);
        expect(document.getElementById('rl-toast-msg').textContent).toMatch(/Cleared 1/);
    });

    test('clicking Undo restores list and re-checks toggle', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        document.getElementById('rl-toast-undo').click();
        expect(loadList()).toHaveLength(1);
        expect(loadOptInState()).toBe(true);
        expect(cb.checked).toBe(true);
        expect(document.getElementById('rl-toast').hidden).toBe(true);
    });

    test('timeout commits the action (toast hides, list stays cleared)', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        jest.advanceTimersByTime(TOAST_TIMEOUT_MS + 100);
        expect(loadList()).toEqual([]);
        expect(document.getElementById('rl-toast').hidden).toBe(true);
    });

    test('toast container has accessibility attributes', () => {
        const toast = document.getElementById('rl-toast');
        expect(toast.getAttribute('role')).toBe('status');
        expect(toast.getAttribute('aria-live')).toBe('polite');
    });
});

// ── Clear button ─────────────────────────────────────────────────────────────

describe('clear button flow', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        __handlers = attachHandlers();
        jest.useFakeTimers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
        jest.useRealTimers();
    });

    test('clears list and shows toast when list nonempty', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        document.getElementById('recent-lookups-clear').click();
        expect(loadList()).toEqual([]);
        expect(document.getElementById('rl-toast').hidden).toBe(false);
    });

    test('Undo restores list, opt-in stays on', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        document.getElementById('recent-lookups-clear').click();
        document.getElementById('rl-toast-undo').click();
        expect(loadList()).toHaveLength(1);
        expect(loadOptInState()).toBe(true);
    });

    test('does nothing when list is empty', () => {
        saveOptInState(true);
        document.getElementById('recent-lookups-clear').click();
        expect(document.getElementById('rl-toast').hidden).toBe(true);
    });
});

// ── List item click → fill textarea ─────────────────────────────────────────

describe('list item click', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        __handlers = attachHandlers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
    });

    test('clicking an entry fills the textarea with stored IPs', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1', '2.2.2.2'], count: 2, ts: 100 }]);
        // Re-render after seeding
        document.dispatchEvent(new CustomEvent('ip2geo:lookup_submit', {
            detail: { ips: [], count: 0 }
        }));
        // Now there are 2 items in the list (the seeded one + the empty submit)
        // Click the first rendered item (which is the newest = the empty submit)
        const items = document.querySelectorAll('.recent-lookup-item');
        expect(items.length).toBeGreaterThan(0);
        // Click the entry with idx=0 (the seeded one)
        const seededBtn = Array.from(items).find(b => b.dataset.idx === '0');
        seededBtn.click();
        const textarea = document.getElementById('message');
        expect(textarea.value).toContain('1.1.1.1');
        expect(textarea.value).toContain('2.2.2.2');
    });
});

// ── Custom event integration ─────────────────────────────────────────────────

describe('ip2geo:lookup_submit integration', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        __handlers = attachHandlers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
    });

    test('opt-in OFF: lookup_submit event does not store anything', () => {
        document.dispatchEvent(new CustomEvent('ip2geo:lookup_submit', {
            detail: { ips: ['1.1.1.1'], count: 1 }
        }));
        expect(loadList()).toEqual([]);
    });

    test('opt-in ON: lookup_submit event appends entry', () => {
        saveOptInState(true);
        document.dispatchEvent(new CustomEvent('ip2geo:lookup_submit', {
            detail: { ips: ['1.1.1.1'], count: 1 }
        }));
        const list = loadList();
        expect(list).toHaveLength(1);
        expect(list[0].count).toBe(1);
    });
});

// ── localStorage unavailable ─────────────────────────────────────────────────

describe('localStorage unavailable', () => {
    let __handlers;
    let __spy;

    beforeEach(() => {
        buildDOM();
        // Force isStorageAvailable() to return false by mocking setItem to throw
        __spy = jest.spyOn(Storage.prototype, 'setItem')
            .mockImplementation(() => { throw new Error('disabled'); });
        __handlers = attachHandlers();
    });

    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
        if (__spy) __spy.mockRestore();
    });

    test('toggle row stays hidden', () => {
        const row = document.getElementById('rl-optin-row');
        expect(row.hidden).toBe(true);
    });

    test('lookup_submit dispatch does not throw', () => {
        expect(() => {
            document.dispatchEvent(new CustomEvent('ip2geo:lookup_submit', {
                detail: { ips: ['1.1.1.1'], count: 1 }
            }));
        }).not.toThrow();
    });
});
