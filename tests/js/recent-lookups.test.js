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
    try { return window.localStorage.getItem(OPTIN_KEY) !== '0'; }
    catch (_) { return true; }
}

function saveOptInState(value) {
    try {
        window.localStorage.setItem(OPTIN_KEY, value ? '1' : '0');
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
    test('returns true on missing key (default ON / opt-out)', () => {
        expect(loadOptInState()).toBe(true);
    });

    test('returns true on key value "1"', () => {
        window.localStorage.setItem(OPTIN_KEY, '1');
        expect(loadOptInState()).toBe(true);
    });

    test('returns false on key value "0" (explicit opt-out)', () => {
        window.localStorage.setItem(OPTIN_KEY, '0');
        expect(loadOptInState()).toBe(false);
    });

    test('returns true on other value (treats unknown as default ON)', () => {
        window.localStorage.setItem(OPTIN_KEY, 'true');
        expect(loadOptInState()).toBe(true);
    });
});

// ── saveOptInState ────────────────────────────────────────────────────────────

describe('saveOptInState', () => {
    test('true sets key to "1"', () => {
        saveOptInState(true);
        expect(window.localStorage.getItem(OPTIN_KEY)).toBe('1');
    });

    test('false sets key to "0" (persists explicit opt-out)', () => {
        window.localStorage.setItem(OPTIN_KEY, '1');
        saveOptInState(false);
        expect(window.localStorage.getItem(OPTIN_KEY)).toBe('0');
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
        saveOptInState(false); // explicit opt-out (default is ON now)
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
        <div id="workbench-root"></div>
        <form id="iplookup">
            <textarea id="message"></textarea>
            <div class="actions-row">
                <input type="submit" class="button submit" value="Look Up IP Addresses" />
                <button type="button" id="rl-recent-btn" class="button alt rl-recent-btn"
                        aria-haspopup="menu" aria-expanded="false" aria-controls="rl-menu" hidden>
                    Recent <span aria-hidden="true">▾</span>
                </button>
                <div id="rl-menu" class="wb-menu rl-menu" role="menu" aria-labelledby="rl-recent-btn" hidden></div>
            </div>
            <div id="rl-optin-row" class="opt-in-toggle" hidden>
                <label class="opt-in">
                    <input type="checkbox" id="rl-optin">
                </label>
            </div>
        </form>
        <div id="rl-toast" role="status" aria-live="polite" hidden>
            <span id="rl-toast-msg"></span>
            <button type="button" id="rl-toast-undo">Undo</button>
        </div>
    `;
    // jsdom doesn't implement real form submission; workbench.js's own submit
    // listener always calls preventDefault(), so mirror that here to avoid
    // its "not implemented: HTMLFormElement.prototype.submit" console noise.
    document.getElementById('iplookup').addEventListener('submit', (e) => e.preventDefault());
}

// Mirror of the production RL module in assets/js/ip2geo-app.js (menu render,
// open/close/keyboard, select/clear handlers, toast). Kept in lockstep with
// the real implementation; storage helpers above are the shared source.
function attachHandlers() {
    let toastTimer = null;
    let pendingUndo = null;
    let pendingUndoTracked = true;
    let btn = null;
    let menu = null;

    function lastRawText() {
        const root = document.getElementById('workbench-root');
        return (root && typeof root._wbLastRawText === 'function') ? root._wbLastRawText() : '';
    }

    function menuItems() {
        return menu ? Array.from(menu.querySelectorAll('.wb-menu-item')) : [];
    }

    function renderMenu() {
        menu.innerHTML = '';
        const listWrap = document.createElement('div');
        listWrap.className = 'rl-menu-list';
        listWrap.setAttribute('role', 'group');
        listWrap.setAttribute('aria-label', 'Saved lookups');
        menu.appendChild(listWrap);

        const items = loadList();

        if (!items.length) {
            const empty = document.createElement('button');
            empty.type = 'button';
            empty.className = 'wb-menu-item';
            empty.setAttribute('role', 'menuitem');
            empty.setAttribute('tabindex', '-1');
            empty.setAttribute('aria-disabled', 'true');
            const head = document.createElement('span');
            head.textContent = 'No saved lookups yet';
            const note = document.createElement('span');
            note.className = 'wb-menu-note';
            note.textContent = 'Lookups you run are saved here, in this browser only.';
            empty.appendChild(head);
            empty.appendChild(note);
            listWrap.appendChild(empty);
            return;
        }

        const now = Date.now();
        items.slice().reverse().forEach((entry, revIdx) => {
            const origIdx = items.length - 1 - revIdx;
            const itemBtn = document.createElement('button');
            itemBtn.type = 'button';
            itemBtn.className = 'wb-menu-item';
            itemBtn.setAttribute('role', 'menuitem');
            itemBtn.setAttribute('tabindex', '-1');
            itemBtn.dataset.idx = String(origIdx);

            const head = document.createElement('span');
            head.className = 'rl-item-head';
            const countEl = document.createElement('span');
            countEl.className = 'recent-lookup-count';
            countEl.textContent = `${entry.count.toLocaleString()} IP${entry.count !== 1 ? 's' : ''}`;
            const timeEl = document.createElement('span');
            timeEl.className = 'recent-lookup-time';
            timeEl.textContent = relativeTime(entry.ts, now);
            head.appendChild(countEl);
            head.appendChild(timeEl);

            let preview = entry.ips.slice(0, 3).join(', ');
            if (entry.count > 3) preview += `, +${(entry.count - 3).toLocaleString()} more`;
            const previewEl = document.createElement('span');
            previewEl.className = 'wb-menu-note rl-item-preview';
            previewEl.textContent = preview;

            itemBtn.appendChild(head);
            itemBtn.appendChild(previewEl);
            listWrap.appendChild(itemBtn);
        });

        const sep = document.createElement('div');
        sep.className = 'rl-menu-sep';
        sep.setAttribute('role', 'separator');
        menu.appendChild(sep);

        const clearBtn = document.createElement('button');
        clearBtn.type = 'button';
        clearBtn.className = 'wb-menu-item rl-menu-clear';
        clearBtn.setAttribute('role', 'menuitem');
        clearBtn.setAttribute('tabindex', '-1');
        clearBtn.textContent = 'Clear saved lookups';
        menu.appendChild(clearBtn);
    }

    function syncButtonVisibility() {
        if (btn) btn.hidden = !loadOptInState();
    }

    function openMenu() {
        renderMenu();
        menu.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
        const first = menuItems()[0];
        if (first) first.focus();
        document.addEventListener('click', onDocClick, true);
    }

    function closeMenu(returnFocus) {
        menu.hidden = true;
        btn.setAttribute('aria-expanded', 'false');
        document.removeEventListener('click', onDocClick, true);
        if (returnFocus) btn.focus();
    }

    function onDocClick(event) {
        if (!btn.contains(event.target) && !menu.contains(event.target)) closeMenu();
    }

    function onMenuKeydown(event) {
        const list = menuItems();
        const idx = list.indexOf(document.activeElement);
        if (event.key === 'ArrowDown') {
            event.preventDefault();
            list[(idx + 1) % list.length].focus();
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            list[(idx - 1 + list.length) % list.length].focus();
        } else if (event.key === 'Home') {
            event.preventDefault();
            list[0].focus();
        } else if (event.key === 'End') {
            event.preventDefault();
            list[list.length - 1].focus();
        } else if (event.key === 'Escape') {
            event.preventDefault();
            closeMenu(true);
        } else if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            document.activeElement.click();
        } else if (event.key === 'Tab') {
            closeMenu();
        }
    }

    function onMenuClick(event) {
        const itemBtn = event.target.closest && event.target.closest('.wb-menu-item');
        if (!itemBtn || itemBtn.getAttribute('aria-disabled') === 'true') return;
        if (itemBtn.classList.contains('rl-menu-clear')) {
            handleClear();
            return;
        }
        const idx = parseInt(itemBtn.dataset.idx, 10);
        if (!isNaN(idx)) handleSelect(idx);
    }

    function showToast(message, undoFn, trackUndo) {
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
        pendingUndoTracked = trackUndo !== false;
        toast.hidden = false;
        toast.classList.add('rl-toast-visible');
        toastTimer = setTimeout(() => hideToast(false), TOAST_TIMEOUT_MS);
    }

    function hideToast(viaUndo) {
        const toast = document.getElementById('rl-toast');
        if (!toast) return;
        if (viaUndo && typeof pendingUndo === 'function') {
            try { pendingUndo(); } catch (_) {}
            if (pendingUndoTracked) {
                try { window.umami && window.umami.track('recent_lookups_undo'); } catch (_) {}
            }
        }
        pendingUndo = null;
        pendingUndoTracked = true;
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
            try { window.umami && window.umami.track('recent_lookups_optin'); } catch (_) {}
            syncButtonVisibility();
            return;
        }
        const listSnapshot = loadList();
        if (!listSnapshot.length) {
            saveOptInState(false);
            try { window.umami && window.umami.track('recent_lookups_optout'); } catch (_) {}
            syncButtonVisibility();
            return;
        }
        saveOptInState(false);
        clearList();
        syncButtonVisibility();
        closeMenu();
        showToast(`Saving turned off. Cleared ${listSnapshot.length} saved lookup${listSnapshot.length !== 1 ? 's' : ''}.`, () => {
            saveOptInState(true);
            saveList(listSnapshot);
            syncButtonVisibility();
            const optInEl = document.getElementById('rl-optin');
            if (optInEl) optInEl.checked = true;
        });
        setTimeout(() => {
            if (!loadOptInState()) {
                try { window.umami && window.umami.track('recent_lookups_optout'); } catch (_) {}
            }
        }, TOAST_TIMEOUT_MS + 50);
    }

    function handleClear() {
        const listSnapshot = loadList();
        closeMenu(true);
        if (!listSnapshot.length) return;
        clearList();
        showToast(`Cleared ${listSnapshot.length} saved lookup${listSnapshot.length !== 1 ? 's' : ''}.`, () => {
            saveList(listSnapshot);
        });
        setTimeout(() => {
            if (!loadList().length) {
                try { window.umami && window.umami.track('recent_lookups_clear'); } catch (_) {}
            }
        }, TOAST_TIMEOUT_MS + 50);
    }

    function handleSelect(idx) {
        const items = loadList();
        const entry = items[idx];
        if (!entry) return;
        const textarea = document.getElementById('message');
        const form = document.getElementById('iplookup');
        if (!textarea || !form) return;

        try { window.umami && window.umami.track('recent_lookups_use'); } catch (_) {}
        closeMenu(true);

        const priorText = textarea.value;
        const isUnsent = priorText !== '' && priorText !== lastRawText();

        textarea.value = entry.ips.join('\n');
        form.requestSubmit();

        if (isUnsent) {
            showToast('Replaced your unsent paste.', () => {
                textarea.value = priorText;
            }, false);
        }
    }

    function handleLookupSubmit(event) {
        const detail = event.detail || {};
        appendLookup(detail.ips, detail.count);
    }

    // Mirrors production's early `if (!isStorageAvailable()) return;`: the
    // toggle row and Recent button are never touched when storage is blocked.
    if (isStorageAvailable()) {
        const row = document.getElementById('rl-optin-row');
        const optInEl = document.getElementById('rl-optin');
        btn = document.getElementById('rl-recent-btn');
        menu = document.getElementById('rl-menu');
        if (row && optInEl && btn && menu) {
            row.hidden = false;
            optInEl.checked = loadOptInState();
            syncButtonVisibility();
            optInEl.addEventListener('change', handleToggleChange);
            btn.addEventListener('click', () => {
                if (menu.hidden) openMenu(); else closeMenu();
            });
            btn.addEventListener('keydown', (event) => {
                if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    openMenu();
                }
            });
            menu.addEventListener('keydown', onMenuKeydown);
            menu.addEventListener('click', onMenuClick);
        }
    }
    const undoBtn = document.getElementById('rl-toast-undo');
    if (undoBtn) undoBtn.addEventListener('click', () => hideToast(true));
    document.addEventListener('ip2geo:lookup_submit', handleLookupSubmit);

    return {
        openMenu,
        closeMenu,
        handleSelect,
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

    test('checking the toggle saves opt-in and shows the Recent button', () => {
        const cb = document.getElementById('rl-optin');
        cb.checked = true;
        cb.dispatchEvent(new Event('change'));
        expect(loadOptInState()).toBe(true);
        expect(document.getElementById('rl-recent-btn').hidden).toBe(false);
    });

    test('unchecking with empty list: silent off, no toast, Recent hidden', () => {
        saveOptInState(true);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        expect(loadOptInState()).toBe(false);
        expect(document.getElementById('rl-toast').hidden).toBe(true);
        expect(document.getElementById('rl-recent-btn').hidden).toBe(true);
    });

    test('unchecking with nonempty list: clears, hides Recent, shows toast with new copy', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        expect(loadList()).toEqual([]);
        expect(document.getElementById('rl-recent-btn').hidden).toBe(true);
        expect(document.getElementById('rl-toast').hidden).toBe(false);
        expect(document.getElementById('rl-toast-msg').textContent).toBe('Saving turned off. Cleared 1 saved lookup.');
    });

    test('unchecking with a plural list uses plural copy', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }, { ips: ['2.2.2.2'], count: 1, ts: 200 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        expect(document.getElementById('rl-toast-msg').textContent).toBe('Saving turned off. Cleared 2 saved lookups.');
    });

    test('Undo after opt-out restores the list, the toggle, and the Recent button (acceptance 10)', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        document.getElementById('rl-toast-undo').click();
        expect(loadList()).toHaveLength(1);
        expect(loadOptInState()).toBe(true);
        expect(cb.checked).toBe(true);
        expect(document.getElementById('rl-recent-btn').hidden).toBe(false);
    });

    test('re-ticking after an opt-out clear shows Recent with the empty state (acceptance 10/11)', () => {
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        const cb = document.getElementById('rl-optin');
        cb.checked = false;
        cb.dispatchEvent(new Event('change'));
        jest.advanceTimersByTime(TOAST_TIMEOUT_MS + 100); // commit, no undo
        cb.checked = true;
        cb.dispatchEvent(new Event('change'));
        expect(document.getElementById('rl-recent-btn').hidden).toBe(false);
        __handlers.openMenu();
        const items = document.querySelectorAll('#rl-menu .wb-menu-item');
        expect(items.length).toBe(1);
        expect(items[0].getAttribute('aria-disabled')).toBe('true');
        expect(items[0].textContent).toContain('No saved lookups yet');
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

// ── Menu open/close and keyboard (acceptance criteria 3, 4) ──────────────────

describe('menu open/close and keyboard', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        saveOptInState(true);
        saveList([
            { ips: ['1.1.1.1'], count: 1, ts: 100 },
            { ips: ['2.2.2.2'], count: 1, ts: 200 },
        ]);
        __handlers = attachHandlers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
    });

    test('clicking Recent opens the menu, sets aria-expanded, and focuses the first item', () => {
        const btn = document.getElementById('rl-recent-btn');
        btn.click();
        expect(document.getElementById('rl-menu').hidden).toBe(false);
        expect(btn.getAttribute('aria-expanded')).toBe('true');
        expect(document.activeElement.classList.contains('wb-menu-item')).toBe(true);
    });

    test('a second click closes the menu and resets aria-expanded', () => {
        const btn = document.getElementById('rl-recent-btn');
        btn.click();
        btn.click();
        expect(document.getElementById('rl-menu').hidden).toBe(true);
        expect(btn.getAttribute('aria-expanded')).toBe('false');
    });

    test('Escape closes the menu and returns focus to Recent', () => {
        const btn = document.getElementById('rl-recent-btn');
        btn.click();
        document.getElementById('rl-menu').dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
        expect(document.getElementById('rl-menu').hidden).toBe(true);
        expect(document.activeElement).toBe(btn);
    });

    test('Tab closes the menu without forcing focus back to Recent', () => {
        const btn = document.getElementById('rl-recent-btn');
        btn.click();
        document.getElementById('rl-menu').dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
        expect(document.getElementById('rl-menu').hidden).toBe(true);
    });

    test('a click outside the menu closes it', () => {
        document.getElementById('rl-recent-btn').click();
        document.body.click();
        expect(document.getElementById('rl-menu').hidden).toBe(true);
    });

    test('ArrowDown/ArrowUp wrap, with Clear as the last stop', () => {
        document.getElementById('rl-recent-btn').click();
        const menu = document.getElementById('rl-menu');
        const items = () => Array.from(menu.querySelectorAll('.wb-menu-item'));
        expect(items().length).toBe(3); // 2 entries + Clear
        expect(document.activeElement).toBe(items()[0]);

        menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowUp', bubbles: true }));
        expect(document.activeElement).toBe(items()[items().length - 1]);
        expect(document.activeElement.classList.contains('rl-menu-clear')).toBe(true);

        menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
        expect(document.activeElement).toBe(items()[0]);
    });

    test('Home/End jump to the first and last item', () => {
        document.getElementById('rl-recent-btn').click();
        const menu = document.getElementById('rl-menu');
        const items = Array.from(menu.querySelectorAll('.wb-menu-item'));
        menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', bubbles: true }));
        expect(document.activeElement).toBe(items[items.length - 1]);
        menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
        expect(document.activeElement).toBe(items[0]);
    });

    test('Enter/Space/ArrowDown on Recent opens the menu with focus on the first item', () => {
        const btn = document.getElementById('rl-recent-btn');
        btn.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true }));
        expect(document.getElementById('rl-menu').hidden).toBe(false);
        expect(document.activeElement).toBe(document.querySelectorAll('#rl-menu .wb-menu-item')[0]);
    });
});

// ── Empty state (acceptance criteria 11) ──────────────────────────────────────

describe('empty state', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        saveOptInState(true);
        __handlers = attachHandlers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
    });

    test('shows one disabled item, no separator and no Clear item', () => {
        document.getElementById('rl-recent-btn').click();
        const menu = document.getElementById('rl-menu');
        const items = menu.querySelectorAll('.wb-menu-item');
        expect(items.length).toBe(1);
        expect(items[0].getAttribute('aria-disabled')).toBe('true');
        expect(items[0].textContent).toContain('No saved lookups yet');
        expect(items[0].textContent).toContain('Lookups you run are saved here, in this browser only.');
        expect(menu.querySelectorAll('.rl-menu-sep').length).toBe(0);
        expect(menu.querySelectorAll('.rl-menu-clear').length).toBe(0);
    });

    test('the disabled item is focusable, and Enter/Space on it does nothing', () => {
        window.umami = { track: jest.fn() };
        document.getElementById('rl-recent-btn').click();
        expect(document.activeElement.getAttribute('aria-disabled')).toBe('true');
        document.getElementById('rl-menu').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
        expect(window.umami.track).not.toHaveBeenCalled();
        expect(document.getElementById('rl-menu').hidden).toBe(false); // still open, nothing happened
        delete window.umami;
    });
});

// ── Menu contents (acceptance criteria 6) ─────────────────────────────────────

describe('menu entry contents', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        saveOptInState(true);
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
    });

    test('shows count, age and a 3-IP preview; no "+N more" at exactly 3 IPs', () => {
        saveList([{ ips: ['192.0.2.10', '198.51.100.7', '203.0.113.44'], count: 3, ts: Date.now() - 2 * 3600 * 1000 }]);
        __handlers = attachHandlers();
        document.getElementById('rl-recent-btn').click();
        const item = document.querySelector('#rl-menu .wb-menu-item');
        expect(item.querySelector('.recent-lookup-count').textContent).toBe('3 IPs');
        expect(item.querySelector('.recent-lookup-time').textContent).toBe('2 hr ago');
        expect(item.querySelector('.rl-item-preview').textContent).toBe('192.0.2.10, 198.51.100.7, 203.0.113.44');
    });

    test('appends "+N more" (localised) beyond the first 3 IPs', () => {
        saveList([{ ips: ['192.0.2.10', '198.51.100.7', '203.0.113.44', '9.9.9.9'], count: 10000, ts: Date.now() }]);
        __handlers = attachHandlers();
        document.getElementById('rl-recent-btn').click();
        const item = document.querySelector('#rl-menu .wb-menu-item');
        expect(item.querySelector('.recent-lookup-count').textContent).toBe('10,000 IPs');
        expect(item.querySelector('.rl-item-preview').textContent).toBe('192.0.2.10, 198.51.100.7, 203.0.113.44, +9,997 more');
    });

    test('singular "1 IP" for a single-address entry', () => {
        saveList([{ ips: ['8.8.8.8'], count: 1, ts: Date.now() }]);
        __handlers = attachHandlers();
        document.getElementById('rl-recent-btn').click();
        expect(document.querySelector('.recent-lookup-count').textContent).toBe('1 IP');
    });
});

// ── Selecting a menu entry (acceptance criteria 7, 8) ─────────────────────────

describe('selecting a menu entry', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1', '2.2.2.2'], count: 2, ts: 100 }]);
        __handlers = attachHandlers();
        jest.useFakeTimers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
        jest.useRealTimers();
    });

    test('fills the textarea, runs the lookup via form.requestSubmit(), fires recent_lookups_use once, and closes the menu', () => {
        window.umami = { track: jest.fn() };
        const form = document.getElementById('iplookup');
        const submitSpy = jest.fn((e) => e.preventDefault());
        form.addEventListener('submit', submitSpy);

        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .wb-menu-item[data-idx="0"]').click();

        const textarea = document.getElementById('message');
        expect(textarea.value).toBe('1.1.1.1\n2.2.2.2');
        expect(submitSpy).toHaveBeenCalledTimes(1);
        expect(window.umami.track).toHaveBeenCalledTimes(1);
        expect(window.umami.track).toHaveBeenCalledWith('recent_lookups_use');
        expect(document.getElementById('rl-menu').hidden).toBe(true);
        expect(document.activeElement).toBe(document.getElementById('rl-recent-btn'));
        delete window.umami;
    });

    test('moving an entry to the top: re-running via ip2geo:lookup_submit dedupes onto one entry', () => {
        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .wb-menu-item[data-idx="0"]').click();
        // The workbench fires this event once the (mocked) lookup succeeds.
        document.dispatchEvent(new CustomEvent('ip2geo:lookup_submit', {
            detail: { ips: ['1.1.1.1', '2.2.2.2'], count: 2 }
        }));
        expect(loadList()).toHaveLength(1);
    });

    test('no toast when the textarea was empty before selecting', () => {
        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .wb-menu-item[data-idx="0"]').click();
        expect(document.getElementById('rl-toast').hidden).toBe(true);
    });

    test('no toast when the textarea already held the last looked-up text', () => {
        const root = document.getElementById('workbench-root');
        root._wbLastRawText = () => '9.9.9.9';
        document.getElementById('message').value = '9.9.9.9';

        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .wb-menu-item[data-idx="0"]').click();
        expect(document.getElementById('rl-toast').hidden).toBe(true);
    });

    test('forgiveness toast when the textarea held different unsent text; Undo restores it exactly and fires no recent_lookups_undo (acceptance 8)', () => {
        window.umami = { track: jest.fn() };
        const root = document.getElementById('workbench-root');
        root._wbLastRawText = () => '9.9.9.9'; // last successful lookup
        document.getElementById('message').value = 'unsent draft text';

        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .wb-menu-item[data-idx="0"]').click();

        const toast = document.getElementById('rl-toast');
        expect(toast.hidden).toBe(false);
        expect(document.getElementById('rl-toast-msg').textContent).toBe('Replaced your unsent paste.');
        expect(document.getElementById('message').value).toBe('1.1.1.1\n2.2.2.2'); // lookup already ran

        window.umami.track.mockClear();
        document.getElementById('rl-toast-undo').click();

        expect(document.getElementById('message').value).toBe('unsent draft text');
        expect(window.umami.track).not.toHaveBeenCalledWith('recent_lookups_undo');
    });
});

// ── Clear saved lookups menu item (acceptance criteria 9) ─────────────────────

describe('Clear saved lookups (menu item)', () => {
    let __handlers;
    beforeEach(() => {
        buildDOM();
        saveOptInState(true);
        saveList([{ ips: ['1.1.1.1'], count: 1, ts: 100 }]);
        __handlers = attachHandlers();
        jest.useFakeTimers();
    });
    afterEach(() => {
        if (__handlers && __handlers.detach) __handlers.detach();
        jest.useRealTimers();
    });

    test('clears the list, closes the menu, and shows a toast with the new copy', () => {
        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .rl-menu-clear').click();
        expect(loadList()).toEqual([]);
        expect(document.getElementById('rl-menu').hidden).toBe(true);
        expect(document.getElementById('rl-toast').hidden).toBe(false);
        expect(document.getElementById('rl-toast-msg').textContent).toBe('Cleared 1 saved lookup.');
    });

    test('Undo restores the list; opt-in stays on', () => {
        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .rl-menu-clear').click();
        document.getElementById('rl-toast-undo').click();
        expect(loadList()).toHaveLength(1);
        expect(loadOptInState()).toBe(true);
    });

    test('recent_lookups_clear fires only after the 6s commit window, not on click', () => {
        window.umami = { track: jest.fn() };
        document.getElementById('rl-recent-btn').click();
        document.querySelector('#rl-menu .rl-menu-clear').click();
        expect(window.umami.track).not.toHaveBeenCalledWith('recent_lookups_clear');
        jest.advanceTimersByTime(TOAST_TIMEOUT_MS + 100);
        expect(window.umami.track).toHaveBeenCalledWith('recent_lookups_clear');
        delete window.umami;
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
        saveOptInState(false); // explicit opt-out (default is ON now)
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

// ── localStorage unavailable (acceptance criteria 13) ─────────────────────────

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

    test('toggle row and Recent button stay hidden', () => {
        expect(document.getElementById('rl-optin-row').hidden).toBe(true);
        expect(document.getElementById('rl-recent-btn').hidden).toBe(true);
    });

    test('lookup_submit dispatch does not throw', () => {
        expect(() => {
            document.dispatchEvent(new CustomEvent('ip2geo:lookup_submit', {
                detail: { ips: ['1.1.1.1'], count: 1 }
            }));
        }).not.toThrow();
    });
});
