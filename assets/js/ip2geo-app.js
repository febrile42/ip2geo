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

})();
