(function () {
    'use strict';

    // ── Stripe cancel restore ──────────────────────────────────────────────
    // If the user cancelled from Stripe and was redirected back with ?cancelled=1,
    // restore their IPs from sessionStorage and re-submit the form automatically.
    (function handleCancel() {
        var params = new URLSearchParams(window.location.search);
        if (!params.get('cancelled')) return;

        // Remove ?cancelled=1 from the URL without a page reload
        history.replaceState(null, '', window.location.pathname);

        window.umami && umami.track('stripe_cancel');

        var pending = sessionStorage.getItem('ip2geo_pending_ips');
        if (pending) {
            sessionStorage.removeItem('ip2geo_pending_ips');
            var textarea = document.getElementById('message');
            var form = document.getElementById('iplookup');
            if (textarea && form) {
                textarea.value = pending;
                // Re-submit via the existing AJAX handler; it fires on the submit button click
                // so we dispatch a click event which the existing listener handles.
                var btn = form.querySelector('input[type="submit"]');
                if (btn) {
                    // Set a flag so the cancel notice shows after results render
                    sessionStorage.setItem('ip2geo_show_cancel_notice', '1');
                    btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                }
            }
        } else {
            // sessionStorage empty (different tab / cleared) — show static notice
            showCancelNotice('Payment cancelled. Paste your IPs again to continue.');
        }
    })();

    function showCancelNotice(msg) {
        var existing = document.getElementById('cancel-notice');
        if (existing) return;
        var notice = document.createElement('div');
        notice.id = 'cancel-notice';
        notice.setAttribute('role', 'status');
        notice.innerHTML = '<span>' + msg + '</span><button aria-label="Dismiss">&#215;</button>';
        notice.querySelector('button').addEventListener('click', function () { notice.remove(); });
        setTimeout(function () { if (notice.parentNode) notice.remove(); }, 8000);
        var intro = document.getElementById('intro');
        if (intro) intro.insertAdjacentElement('afterend', notice);
    }

    // ── CTA button: save IPs to sessionStorage before Stripe redirect ──────
    // The CTA is a form submit (POST to /get-report.php with ip_classified_json).
    // We save the raw textarea value here so we can restore it if the user cancels.
    document.addEventListener('click', function (e) {
        if (!e.target || e.target.id !== 'cta-button') return;
        var textarea = document.getElementById('message');
        if (textarea && textarea.value) {
            sessionStorage.setItem('ip2geo_pending_ips', textarea.value);
        }
        window.umami && umami.track('cta_click');
        // Let the form submit proceed normally
    });

    // ── Row striping ──────────────────────────────────────────────────────
    // nth-child counts hidden rows, breaking alternating colors when filtered.
    // We manage stripes explicitly with a class so only visible rows stripe.
    function restripe() {
        var idx = 0;
        document.querySelectorAll('#results-table tbody:not(#unresolved-rows) tr').forEach(function (row) {
            var hidden = row.classList.contains('row-hidden');
            row.classList.toggle('row-stripe', !hidden && idx % 2 === 0);
            if (!hidden) idx++;
        });
    }

    // ── Filter logic ───────────────────────────────────────────────────────
    function applyFilters() {
        var checkedCountries = new Set(
            Array.from(document.querySelectorAll('.filter-country:checked')).map(function (el) { return el.value; })
        );
        var checkedCategories = new Set(
            Array.from(document.querySelectorAll('.filter-category:checked')).map(function (el) { return el.value; })
        );

        var allRows = document.querySelectorAll('#results-table tbody:not(#unresolved-rows) tr');
        var visible = 0;

        // When the user has an exclusive country selection, empty-CC rows (anycast IPs with
        // no geo data) should be hidden — they don't belong to any selected country.
        // Only pass them through when ALL countries are selected (no filter active).
        var totalCountryChips = document.querySelectorAll('.filter-country').length;
        var allCountriesSelected = checkedCountries.size === totalCountryChips;

        // Per-chip cross-filter counts: how many rows pass the *other* filter dimension
        var catCounts = {};      // rows passing country filter, keyed by category
        var countryCounts = {};  // rows passing category filter, keyed by country

        allRows.forEach(function (row) {
            var country  = row.dataset.country   || '';
            var category = row.dataset.category  || '';
            var countryOk  = (country === '' && allCountriesSelected) || checkedCountries.has(country);
            var categoryOk = checkedCategories.has(category);
            var show = countryOk && categoryOk;
            row.classList.toggle('row-hidden', !show);
            if (show) visible++;

            // Count for category chips: rows that pass the country filter
            if (countryOk) {
                catCounts[category] = (catCounts[category] || 0) + 1;
            }
            // Count for country chips: rows that pass the category filter
            if (categoryOk && country !== '') {
                countryCounts[country] = (countryCounts[country] || 0) + 1;
            }
        });

        restripe();

        // Denominator = all submitted IPs (geo-resolved + unresolved)
        var unresolvedBody = document.getElementById('unresolved-rows');
        var unresolvedCount = unresolvedBody ? unresolvedBody.rows.length : 0;
        var totalEl = document.getElementById('filter-total');
        if (totalEl) totalEl.textContent = allRows.length + unresolvedCount;

        // Numerator: add unresolved to visible count only when that section is expanded
        if (unresolvedBody && unresolvedBody.style.display !== 'none') {
            visible += unresolvedCount;
        }

        // Update the showing count in the summary
        var countEl = document.getElementById('filter-count');
        if (countEl) countEl.textContent = visible;

        // Empty state
        var emptyMsg = document.getElementById('empty-filter-msg');
        if (emptyMsg) emptyMsg.style.display = visible === 0 ? '' : 'none';

        // Update per-chip counts and empty state
        document.querySelectorAll('.filter-category').forEach(function (input) {
            var count = catCounts[input.value] || 0;
            var label = input.closest('label');
            if (!label) return;
            var countEl = label.querySelector('.chip-count');
            if (countEl) countEl.textContent = '(' + count + ')';
            label.classList.toggle('chip--empty', count === 0);
        });
        document.querySelectorAll('.filter-country').forEach(function (input) {
            var count = countryCounts[input.value] || 0;
            var label = input.closest('label');
            if (!label) return;
            var countEl = label.querySelector('.chip-count');
            if (countEl) countEl.textContent = '(' + count + ')';
            label.classList.toggle('chip--empty', count === 0);
        });

        // Regenerate rules immediately so open blocks stay in sync with visible rows
        generateRules();
    }

    // ── Firewall rule generation ───────────────────────────────────────────
    function getVisibleIPs() {
        var ips = [];
        document.querySelectorAll('#results-table tbody:not(#unresolved-rows) tr').forEach(function (row) {
            if (row.classList.contains('row-hidden')) return;
            var ip = row.querySelector('td');
            if (ip) ips.push(ip.textContent.trim());
        });
        return ips;
    }

    function generateRules() {
        var ips = getVisibleIPs();

        var iptablesPre = document.getElementById('rules-iptables-pre');
        var ufwPre      = document.getElementById('rules-ufw-pre');
        var nginxPre    = document.getElementById('rules-nginx-pre');

        if (!ips.length) {
            // All rows filtered out — clear stale rules
            if (iptablesPre) iptablesPre.textContent = '';
            if (ufwPre)      ufwPre.textContent = '';
            if (nginxPre)    nginxPre.textContent = '';
            return;
        }

        if (iptablesPre) {
            iptablesPre.textContent = ips.map(function (ip) {
                return 'iptables -A INPUT -s ' + ip + ' -j DROP';
            }).join('\n');
        }
        if (ufwPre) {
            ufwPre.textContent = ips.map(function (ip) {
                return 'ufw deny from ' + ip + ' to any';
            }).join('\n');
        }
        if (nginxPre) {
            nginxPre.textContent = 'geo $block_ip {\n    default 0;\n' +
                ips.map(function (ip) { return '    ' + ip + ' 1;'; }).join('\n') +
                '\n}';
        }
    }

    // ── Show/hide rule blocks ──────────────────────────────────────────────
    var rulesButtonMap = {
        'rules-iptables': { btnId: 'show-iptables', show: 'Show iptables rules', hide: 'Hide iptables rules' },
        'rules-ufw':      { btnId: 'show-ufw',      show: 'Show ufw rules',      hide: 'Hide ufw rules'      },
        'rules-nginx':    { btnId: 'show-nginx',     show: 'Show nginx block',    hide: 'Hide nginx block'    }
    };

    function toggleRulesBlock(blockId) {
        var block = document.getElementById(blockId);
        if (!block) return;
        var wasHidden = block.style.display === 'none';
        // Close all open blocks and reset all button labels
        ['rules-iptables', 'rules-ufw', 'rules-nginx'].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.style.display = 'none';
            var btn = document.getElementById(rulesButtonMap[id].btnId);
            if (btn) btn.textContent = rulesButtonMap[id].show;
        });
        if (wasHidden) {
            block.style.display = '';
            var btn = document.getElementById(rulesButtonMap[blockId].btnId);
            if (btn) btn.textContent = rulesButtonMap[blockId].hide;
            generateRules();
            window.umami && umami.track('show_rules_' + blockId.replace('rules-', ''));
        }
    }

    document.addEventListener('click', function (e) {
        var id = e.target && e.target.id;
        if (id === 'show-iptables') { toggleRulesBlock('rules-iptables'); return; }
        if (id === 'show-ufw')      { toggleRulesBlock('rules-ufw');      return; }
        if (id === 'show-nginx')    { toggleRulesBlock('rules-nginx');     return; }
    });

    // ── Copy button inside rule blocks ────────────────────────────────────
    document.addEventListener('click', function (e) {
        if (!e.target || !e.target.classList.contains('copy-rules')) return;
        var targetId = e.target.dataset.target;
        var pre = document.getElementById(targetId);
        if (!pre) return;
        navigator.clipboard.writeText(pre.textContent).then(function () {
            var orig = e.target.textContent;
            e.target.textContent = 'Copied!';
            window.umami && umami.track('copy_rules_' + targetId.replace('rules-', '').replace('-pre', ''));
            setTimeout(function () { e.target.textContent = orig; }, 2000);
        });
    });

    // ── Country chip clicks: exclusive-select / shift+click multi-select ─────
    // Plain click  → show ONLY that country (click again to restore all).
    // Shift+click  → toggle this country in/out of the current selection.
    // Keyboard nav → falls through to the change handler below (toggle behaviour).
    document.addEventListener('click', function (e) {
        var label = e.target && e.target.closest('#filter-countries label');
        if (!label) return;

        e.preventDefault(); // stop the label from auto-toggling its checkbox

        var clicked = label.querySelector('input[type="checkbox"]');
        if (!clicked) return;

        var all = Array.from(document.querySelectorAll('.filter-country'));

        if (e.shiftKey) {
            // Shift+click: add or remove this country from the selection
            clicked.checked = !clicked.checked;
            // If nothing would remain checked, restore all
            if (!all.some(function (i) { return i.checked; })) {
                all.forEach(function (i) { i.checked = true; });
            }
        } else {
            var soloActive = all.filter(function (i) { return i.checked; }).length === 1 && clicked.checked;
            if (soloActive) {
                // Clicking the already-lone active chip restores all countries
                all.forEach(function (i) { i.checked = true; });
            } else {
                // Exclusive select: only this country
                all.forEach(function (i) { i.checked = false; });
                clicked.checked = true;
                window.umami && umami.track('filter_country', { country: clicked.value });
            }
        }

        applyFilters();
    });

    // ── Toggle unresolved rows ─────────────────────────────────────────────
    document.addEventListener('click', function (e) {
        if (!e.target || e.target.id !== 'toggle-unresolved') return;
        var unresolvedBody = document.getElementById('unresolved-rows');
        if (!unresolvedBody) return;
        var hidden = unresolvedBody.style.display === 'none';
        unresolvedBody.style.display = hidden ? '' : 'none';
        var n = unresolvedBody.rows.length;
        e.target.textContent = (hidden ? 'Hide ' : 'Show ') + n + ' unresolved IP' + (n !== 1 ? 's' : '');
        applyFilters(); // update "Showing X of Y" to include/exclude unresolved rows
    });

    // ── Wire up filter checkboxes (delegated — works after AJAX inject) ────
    // Handles category chips (always toggle) and keyboard-driven country changes.
    document.addEventListener('change', function (e) {
        if (!e.target) return;
        if (e.target.classList.contains('filter-category')) {
            window.umami && umami.track('filter_category', { category: e.target.value, checked: e.target.checked });
            applyFilters();
        } else if (e.target.classList.contains('filter-country')) {
            applyFilters();
        }
    });

    // ── After AJAX results inject: init filters + show cancel notice ───────
    // The existing AJAX handler in index.php replaces #results via outerHTML.
    // We use a MutationObserver to detect when #results is newly added to the DOM.
    //
    // IMPORTANT: only check addedNodes, not document.getElementById('results').
    // generateRules() writes to <pre> elements which are subtree children of body,
    // so a naive "does #results exist?" check re-fires on every DOM write it causes,
    // creating an infinite loop that freezes the browser tab.
    var observer = new MutationObserver(function (mutations) {
        var resultsAdded = mutations.some(function (m) {
            return Array.from(m.addedNodes).some(function (node) {
                return node.nodeType === 1 &&
                    (node.id === 'results' || (node.querySelector && node.querySelector('#results')));
            });
        });
        if (!resultsAdded) return;
        applyFilters();
        if (sessionStorage.getItem('ip2geo_show_cancel_notice')) {
            sessionStorage.removeItem('ip2geo_show_cancel_notice');
            showCancelNotice('Changed your mind? Your threat report is still ready.');
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });

    // Init filters + stripes + rules on initial server-rendered load
    applyFilters();

    // ── Recent lookups: opt-in localStorage memory ─────────────────────────
    // Default OFF. localStorage only — never sent to the server.
    // Toast-with-undo pattern for destructive actions (toggle-off, clear).
    // See ~/.gstack/projects/febrile42-ip2geo/shadows-develop-eng-review-test-plan-20260426-105859.md
    var RL = (function () {
        var OPTIN_KEY  = 'rl_optin';
        var LIST_KEY   = 'rl_list';
        var MAX_ENTRIES = 20;
        var IPS_PER_ENTRY_CAP = 10000; // matches the form's documented max input
        var TOAST_TIMEOUT_MS = 6000;

        // ── Pure helpers (testable) ────────────────────────────────────────
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
            // Cap entries (keep newest)
            var capped = items.length > MAX_ENTRIES
                ? items.slice(items.length - MAX_ENTRIES)
                : items;
            // On quota exceeded, drop the oldest entry and retry. Loop until
            // it fits or the list is empty (single huge entry can't fit at all).
            // Bound the loop by the list length so we never spin forever.
            while (capped.length > 0) {
                try {
                    window.localStorage.setItem(LIST_KEY, JSON.stringify(capped));
                    return true;
                } catch (_) {
                    capped = capped.slice(1);
                }
            }
            return false; // give up silently — never block the lookup flow
        }

        function clearList() {
            try { window.localStorage.removeItem(LIST_KEY); } catch (_) {}
        }

        function buildEntry(ips, count, nowMs) {
            var safeIps = (ips || []).slice(0, IPS_PER_ENTRY_CAP);
            var safeCount = (typeof count === 'number' && count >= 0) ? count : safeIps.length;
            return { ips: safeIps, count: safeCount, ts: nowMs };
        }

        // Order-dependent fingerprint. Re-running the exact same list
        // (clicked from history, or retyped identically) collapses onto the
        // existing entry. Reordered or edited input gets a fresh entry.
        function fingerprintIps(ips) {
            return (ips || []).join('\n');
        }

        function appendLookup(ips, count) {
            if (!loadOptInState()) return; // OFF: no-op
            var list = loadList();
            var entry = buildEntry(ips, count, Date.now());
            var fp = fingerprintIps(entry.ips);
            // Find existing match (search newest-first — most recent wins on
            // collision, though the list is dedup'd so there should be ≤1).
            var dupeIdx = -1;
            for (var i = list.length - 1; i >= 0; i--) {
                if (fingerprintIps(list[i].ips) === fp) { dupeIdx = i; break; }
            }
            if (dupeIdx >= 0) {
                // Promote: remove old, push fresh entry (new ts, refreshed count).
                list.splice(dupeIdx, 1);
            }
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

        // ── DOM rendering ──────────────────────────────────────────────────
        function renderList() {
            var widget = document.getElementById('recent-lookups');
            var listEl = document.getElementById('recent-lookups-list');
            if (!widget || !listEl) return;

            var optIn = loadOptInState();
            var items = loadList();

            // Hide widget unless opt-in ON and list nonempty
            if (!optIn || !items.length) {
                widget.hidden = true;
                listEl.innerHTML = '';
                return;
            }

            widget.hidden = false;
            listEl.innerHTML = '';
            var now = Date.now();

            // Render newest first as pill chips: "10,000 IPs · 2 min ago".
            // The IP preview (first 3 + ellipsis) lives on the title attribute
            // for hover-to-peek without cluttering the chip surface.
            items.slice().reverse().forEach(function (entry, revIdx) {
                var origIdx = items.length - 1 - revIdx;
                var li = document.createElement('li');
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'recent-lookup-item';
                btn.dataset.idx = String(origIdx);

                var preview = entry.ips.slice(0, 3).join(', ');
                if (entry.count > 3) preview += ', …';
                btn.title = preview;

                var countLabel = entry.count.toLocaleString() + ' IP' + (entry.count !== 1 ? 's' : '');
                var countEl = document.createElement('span');
                countEl.className = 'recent-lookup-count';
                countEl.textContent = countLabel;

                var dotEl = document.createElement('span');
                dotEl.className = 'recent-lookup-dot';
                dotEl.setAttribute('aria-hidden', 'true');
                dotEl.textContent = '·';

                var timeEl = document.createElement('span');
                timeEl.className = 'recent-lookup-time';
                timeEl.textContent = relativeTime(entry.ts, now);

                btn.appendChild(countEl);
                btn.appendChild(dotEl);
                btn.appendChild(timeEl);
                li.appendChild(btn);
                listEl.appendChild(li);
            });
        }

        function fillTextareaFromEntry(idx) {
            var items = loadList();
            var entry = items[idx];
            if (!entry) return;
            var textarea = document.getElementById('message');
            if (!textarea) return;
            textarea.value = entry.ips.join('\n');
            textarea.focus();
            textarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        // ── Toast with undo ────────────────────────────────────────────────
        var toastTimer = null;
        var pendingUndo = null;

        function showToast(message, undoFn) {
            var toast = document.getElementById('rl-toast');
            var msgEl = document.getElementById('rl-toast-msg');
            var undoBtn = document.getElementById('rl-toast-undo');
            if (!toast || !msgEl || !undoBtn) return;

            // Cancel any prior pending toast (commit its action immediately)
            if (toastTimer) {
                clearTimeout(toastTimer);
                toastTimer = null;
                pendingUndo = null;
            }

            msgEl.textContent = message;
            pendingUndo = undoFn;
            toast.hidden = false;
            // Force reflow for slide-in transition
            void toast.offsetWidth;
            toast.classList.add('rl-toast-visible');

            toastTimer = setTimeout(function () {
                hideToast(false); // commit action (do not call undo)
            }, TOAST_TIMEOUT_MS);
        }

        function hideToast(viaUndo) {
            var toast = document.getElementById('rl-toast');
            if (!toast) return;
            if (viaUndo && typeof pendingUndo === 'function') {
                try { pendingUndo(); } catch (_) {}
                try { window.umami && umami.track('recent_lookups_undo'); } catch(_) {}
            }
            pendingUndo = null;
            if (toastTimer) {
                clearTimeout(toastTimer);
                toastTimer = null;
            }
            toast.classList.remove('rl-toast-visible');
            // Hide after transition completes; safe to set hidden immediately
            // since hidden + class removal both prevent display
            toast.hidden = true;
        }

        // ── Event handlers ─────────────────────────────────────────────────
        function handleToggleChange(event) {
            var checked = event.target.checked;
            if (checked) {
                saveOptInState(true);
                try { window.umami && umami.track('recent_lookups_optin'); } catch(_) {}
                renderList();
                return;
            }

            // Unchecking
            var listSnapshot = loadList();
            if (!listSnapshot.length) {
                // Empty list: silent off, no toast
                saveOptInState(false);
                try { window.umami && umami.track('recent_lookups_optout'); } catch(_) {}
                renderList();
                return;
            }

            // Nonempty: optimistic clear + toast with undo
            saveOptInState(false);
            clearList();
            renderList();

            showToast('Cleared ' + listSnapshot.length + ' lookup' + (listSnapshot.length !== 1 ? 's' : '') + '.', function undo() {
                // Restore both the list and the opt-in flag, re-check the toggle
                saveOptInState(true);
                saveList(listSnapshot);
                renderList();
                var optInEl = document.getElementById('rl-optin');
                if (optInEl) optInEl.checked = true;
            });

            // Fire optout event after toast timeout commits (not on uncheck — undo may revert)
            // Use a separate timer so umami fires only when commit happens
            setTimeout(function () {
                if (!loadOptInState()) {
                    try { window.umami && umami.track('recent_lookups_optout'); } catch(_) {}
                }
            }, TOAST_TIMEOUT_MS + 50);
        }

        function handleClearClick() {
            var listSnapshot = loadList();
            if (!listSnapshot.length) return; // nothing to clear

            clearList();
            renderList();

            showToast('Cleared ' + listSnapshot.length + ' lookup' + (listSnapshot.length !== 1 ? 's' : '') + '.', function undo() {
                // Restore list; opt-in stays on
                saveList(listSnapshot);
                renderList();
            });

            setTimeout(function () {
                if (!loadList().length) {
                    try { window.umami && umami.track('recent_lookups_clear'); } catch(_) {}
                }
            }, TOAST_TIMEOUT_MS + 50);
        }

        function handleListClick(event) {
            var btn = event.target.closest && event.target.closest('.recent-lookup-item');
            if (!btn) return;
            var idx = parseInt(btn.dataset.idx, 10);
            if (isNaN(idx)) return;
            fillTextareaFromEntry(idx);
        }

        function handleLookupSubmit(event) {
            var detail = event.detail || {};
            appendLookup(detail.ips, detail.count);
            renderList();
        }

        // ── Init ───────────────────────────────────────────────────────────
        function init() {
            if (!isStorageAvailable()) return; // toggle row stays hidden

            var row = document.getElementById('rl-optin-row');
            var optInEl = document.getElementById('rl-optin');
            if (!row || !optInEl) return;

            // Reveal toggle row only when storage is available
            row.hidden = false;

            // Restore toggle state from localStorage
            optInEl.checked = loadOptInState();

            // Wire up
            optInEl.addEventListener('change', handleToggleChange);

            var clearBtn = document.getElementById('recent-lookups-clear');
            if (clearBtn) clearBtn.addEventListener('click', handleClearClick);

            var listEl = document.getElementById('recent-lookups-list');
            if (listEl) listEl.addEventListener('click', handleListClick);

            var undoBtn = document.getElementById('rl-toast-undo');
            if (undoBtn) undoBtn.addEventListener('click', function () { hideToast(true); });

            document.addEventListener('ip2geo:lookup_submit', handleLookupSubmit);

            renderList();
        }

        return { init: init };
    })();

    RL.init();

})();
