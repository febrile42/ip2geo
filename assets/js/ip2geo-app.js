(function () {
    'use strict';

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
                // No country property (R9/D8): the value comes from the user's own
                // paste, so only the fact that the filter was used is sent.
                window.umami && umami.track('filter_country');
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
        var suffix = e.target.dataset.suffix || ''; // e.g. " (3 IPv6)", set server-side
        e.target.textContent = (hidden ? 'Hide ' : 'Show ') + n + ' unresolved IP' + (n !== 1 ? 's' : '') + suffix;
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

    // ── After AJAX results inject: init filters ─────────────────────────────
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
    });
    observer.observe(document.body, { childList: true, subtree: true });

    // ── "Try a sample log" (D11 + R13 + R16) ────────────────────────────────
    // Loads the public sample-fail2ban.txt (built only from published scanner,
    // DROP and cloud ranges — R13) and, when the visitor's own IP passed
    // FILTER_VALIDATE_IP server-side, appends one benign line with it so the
    // first result includes a "(you)" row. lookup_submit carries sample=true
    // for the resulting lookup (read by the inline submit handler in
    // index.php via window.__ip2geoSampleActive).
    (function () {
        var link = document.getElementById('try-sample-log');
        if (!link) return;

        var textarea = document.getElementById('message');
        if (textarea) {
            // Any manual edit after loading the sample means the next submit
            // is no longer "the sample lookup" as-is.
            textarea.addEventListener('input', function () { window.__ip2geoSampleActive = false; });
        }

        link.addEventListener('click', function (e) {
            e.preventDefault();
            var url = link.dataset.sampleUrl || 'assets/sample-fail2ban.txt';
            fetch(url)
                .then(function (resp) {
                    if (!resp.ok) throw new Error('HTTP ' + resp.status);
                    return resp.text();
                })
                .then(function (text) {
                    var visitorIp = link.dataset.visitorIp || '';
                    if (visitorIp) {
                        text = text.replace(/\n+$/, '') + '\nAccepted publickey for analyst from ' + visitorIp + ' port 52144 ssh2\n';
                    }
                    if (textarea) {
                        textarea.value = text;
                        textarea.focus();
                    }
                    window.__ip2geoSampleActive = true;
                })
                .catch(function () {
                    // Leave the textarea untouched — the link simply didn't do anything.
                });
        });
    })();

    // Init filters + stripes + rules on initial server-rendered load
    applyFilters();

    // ── Recent lookups: opt-out localStorage memory ────────────────────────
    // Default ON (opt-out). localStorage only — never sent to the server.
    // Missing key OR '1' → on; only '0' → off. Existing opt-in users keep '1'.
    // Toast-with-undo pattern for destructive actions (toggle-off, clear).
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

        // ── Menu rendering (IPG-30: replaces the pill list) ──────────────────
        var btn = null;
        var menu = null;

        function lastRawText() {
            var root = document.getElementById('workbench-root');
            return (root && typeof root._wbLastRawText === 'function') ? root._wbLastRawText() : '';
        }

        function menuItems() {
            return menu ? Array.from(menu.querySelectorAll('.wb-menu-item')) : [];
        }

        // Rebuilt from scratch every time the menu opens, so ages are current.
        function renderMenu() {
            menu.innerHTML = '';

            var listWrap = document.createElement('div');
            listWrap.className = 'rl-menu-list';
            listWrap.setAttribute('role', 'group');
            listWrap.setAttribute('aria-label', 'Saved lookups');
            menu.appendChild(listWrap);

            var items = loadList();

            if (!items.length) {
                var empty = document.createElement('button');
                empty.type = 'button';
                empty.className = 'wb-menu-item';
                empty.setAttribute('role', 'menuitem');
                empty.setAttribute('tabindex', '-1');
                empty.setAttribute('aria-disabled', 'true');
                empty.appendChild(document.createElement('span')).textContent = 'No saved lookups yet';
                var emptyNote = document.createElement('span');
                emptyNote.className = 'wb-menu-note';
                emptyNote.textContent = 'Lookups you run are saved here, in this browser only.';
                empty.appendChild(emptyNote);
                listWrap.appendChild(empty);
                return;
            }

            var now = Date.now();

            // Newest first: count, age and a 3-IP preview as visible text
            // (not a title tooltip, so touch and keyboard users can read it).
            items.slice().reverse().forEach(function (entry, revIdx) {
                var origIdx = items.length - 1 - revIdx;
                var itemBtn = document.createElement('button');
                itemBtn.type = 'button';
                itemBtn.className = 'wb-menu-item';
                itemBtn.setAttribute('role', 'menuitem');
                itemBtn.setAttribute('tabindex', '-1');
                itemBtn.dataset.idx = String(origIdx);

                var head = document.createElement('span');
                head.className = 'rl-item-head';

                var countEl = document.createElement('span');
                countEl.className = 'recent-lookup-count';
                countEl.textContent = entry.count.toLocaleString() + ' IP' + (entry.count !== 1 ? 's' : '');

                var dotEl = document.createElement('span');
                dotEl.className = 'recent-lookup-dot';
                dotEl.setAttribute('aria-hidden', 'true');
                dotEl.textContent = '·';

                var timeEl = document.createElement('span');
                timeEl.className = 'recent-lookup-time';
                timeEl.textContent = relativeTime(entry.ts, now);

                head.appendChild(countEl);
                head.appendChild(dotEl);
                head.appendChild(timeEl);

                var preview = entry.ips.slice(0, 3).join(', ');
                if (entry.count > 3) preview += ', +' + (entry.count - 3).toLocaleString() + ' more';
                var previewEl = document.createElement('span');
                previewEl.className = 'wb-menu-note rl-item-preview';
                previewEl.textContent = preview;

                itemBtn.appendChild(head);
                itemBtn.appendChild(previewEl);
                listWrap.appendChild(itemBtn);
            });

            // Pinned below the scrolling list rather than placed at its end,
            // so it never scrolls out of reach even at the 20-entry cap.
            var sep = document.createElement('div');
            sep.className = 'rl-menu-sep';
            sep.setAttribute('role', 'separator');
            menu.appendChild(sep);

            var clearBtn = document.createElement('button');
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

        // ── Open / close (WAI-ARIA menu button pattern, matches Export ▾'s
        // renderExportMenu() in workbench.js, plus Home/End) ─────────────────
        function openMenu() {
            renderMenu();
            menu.hidden = false;
            btn.setAttribute('aria-expanded', 'true');
            var first = menuItems()[0];
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
            var list = menuItems();
            var idx = list.indexOf(document.activeElement);
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
            var itemBtn = event.target.closest && event.target.closest('.wb-menu-item');
            if (!itemBtn || itemBtn.getAttribute('aria-disabled') === 'true') return;
            if (itemBtn.classList.contains('rl-menu-clear')) {
                handleClear();
                return;
            }
            var idx = parseInt(itemBtn.dataset.idx, 10);
            if (!isNaN(idx)) handleSelect(idx);
        }

        // ── Toast with undo ────────────────────────────────────────────────
        var toastTimer = null;
        var pendingUndo = null;
        var pendingUndoTracked = true; // recent_lookups_undo fires only for clear/opt-out, not the forgiveness toast

        function showToast(message, undoFn, trackUndo) {
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
            pendingUndoTracked = trackUndo !== false;
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
                if (pendingUndoTracked) {
                    try { window.umami && umami.track('recent_lookups_undo'); } catch(_) {}
                }
            }
            pendingUndo = null;
            pendingUndoTracked = true;
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
                syncButtonVisibility();
                return;
            }

            // Unchecking
            var listSnapshot = loadList();
            if (!listSnapshot.length) {
                // Empty list: silent off, no toast
                saveOptInState(false);
                try { window.umami && umami.track('recent_lookups_optout'); } catch(_) {}
                syncButtonVisibility();
                return;
            }

            // Nonempty: optimistic clear + toast with undo
            saveOptInState(false);
            clearList();
            syncButtonVisibility();
            closeMenu();

            showToast('Saving turned off. Cleared ' + listSnapshot.length + ' saved lookup' + (listSnapshot.length !== 1 ? 's' : '') + '.', function undo() {
                // Restore both the list and the opt-in flag, re-check the toggle
                saveOptInState(true);
                saveList(listSnapshot);
                syncButtonVisibility();
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

        function handleClear() {
            var listSnapshot = loadList();
            closeMenu(true);
            if (!listSnapshot.length) return; // nothing to clear

            clearList();

            showToast('Cleared ' + listSnapshot.length + ' saved lookup' + (listSnapshot.length !== 1 ? 's' : '') + '.', function undo() {
                // Restore list; opt-in stays on
                saveList(listSnapshot);
            });

            setTimeout(function () {
                if (!loadList().length) {
                    try { window.umami && umami.track('recent_lookups_clear'); } catch(_) {}
                }
            }, TOAST_TIMEOUT_MS + 50);
        }

        // Selecting an entry fills the textarea and runs the lookup through
        // the same path as clicking "Look Up IP Addresses" (form.requestSubmit()
        // triggers workbench.js's own submit listener). If the textarea held
        // unsent text, that text is preserved via an undo toast first.
        function handleSelect(idx) {
            var items = loadList();
            var entry = items[idx];
            if (!entry) return;

            var textarea = document.getElementById('message');
            var form = document.getElementById('iplookup');
            if (!textarea || !form) return;

            // No properties: counts that the feature was used, never what was restored.
            try { window.umami && umami.track('recent_lookups_use'); } catch(_) {}

            closeMenu(true);

            var priorText = textarea.value;
            var isUnsent = priorText !== '' && priorText !== lastRawText();

            textarea.value = entry.ips.join('\n');
            form.requestSubmit();

            if (isUnsent) {
                showToast('Replaced your unsent paste.', function undo() {
                    textarea.value = priorText;
                }, false); // forgiveness toast: no recent_lookups_undo event
            }
        }

        function handleLookupSubmit(event) {
            var detail = event.detail || {};
            appendLookup(detail.ips, detail.count);
        }

        // ── Init ───────────────────────────────────────────────────────────
        function init() {
            if (!isStorageAvailable()) return; // toggle row + Recent button stay hidden

            var row = document.getElementById('rl-optin-row');
            var optInEl = document.getElementById('rl-optin');
            btn = document.getElementById('rl-recent-btn');
            menu = document.getElementById('rl-menu');
            if (!row || !optInEl || !btn || !menu) return;

            // Reveal toggle row only when storage is available
            row.hidden = false;

            // Restore toggle state from localStorage
            optInEl.checked = loadOptInState();
            syncButtonVisibility();

            // Wire up
            optInEl.addEventListener('change', handleToggleChange);

            btn.addEventListener('click', function () {
                if (menu.hidden) openMenu(); else closeMenu();
            });
            btn.addEventListener('keydown', function (event) {
                if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    openMenu();
                }
            });
            menu.addEventListener('keydown', onMenuKeydown);
            menu.addEventListener('click', onMenuClick);

            var undoBtn = document.getElementById('rl-toast-undo');
            if (undoBtn) undoBtn.addEventListener('click', function () { hideToast(true); });

            document.addEventListener('ip2geo:lookup_submit', handleLookupSubmit);
        }

        return { init: init };
    })();

    RL.init();

})();
