<?php
require __DIR__ . '/includes/page-chrome.php';
render_page_open('Changelog — ip2geo.org', 'Release notes for ip2geo.org.');
?>
<section class="report-section">
    <div class="report-inner">
        <div class="section-head">
            <h1>Changelog</h1>
            <span class="section-tag">/ Releases</span>
        </div>

        <div class="prose">
            <h3>4.0.1 — 2026-05-02</h3>
            <p>Discovered the Spamhaus block list wasn't syncing properly on the first of the month. Refactored how that update happens and how Bad Guy ASNs are tracked to keep things up to date.</p>

            <h3>4.0.0 — 2026-04-30</h3>
            <p>The whole site got a new look: modern, restrained, brutalist-leaning. &#129304;</p>
            
            <p><a href="https://vercel.com/font" target="_blank" rel="noopener">Geist</a> for type. A sticky top nav that doesn't take up a third of the viewport. And a real light/dark toggle &mdash; but dark as default, because it's correct.</p>

            <p>The site also lost weight. Until this release, seven scripts were downloaded that came with the original site template years ago and that nothing on the page needed (maybe ever). About 110KB of JavaScript and seven extra HTTP requests, gone. Another 90KB of leftover, unused template CSS went with it. First paint should be snappier, and the codebase is considerably less embarrassing to <code>git clone</code>.</p>

            <h3>3.5.1 — 2026-04-26</h3>
            <p>Fixed the free Threat Report retention wording in the <a href="/privacy.php">privacy policy</a>. Same actual behaviour &mdash; data is still permanently deleted 14 days after generation &mdash; but the old wording could be read as 21 days and that was, you know, wrong.</p>

            <h3>3.5.0 — 2026-04-26</h3>
            <p>Recent Lookups saved &mdash; in local browser storage only. I don't want to save your list, but sometimes you want to pull up that list you pasted five minutes ago. If you want to opt out, just uncheck the box.</p>

            <h3>3.4.0 — 2026-04-18</h3>
            <p>The paid report has always included ready-to-run block scripts. Turns out that's not very helpful if you've never pasted something into a terminal. Click any format to preview the exact commands inline, copy them in one click, and follow the three-step guide below if you're not sure what to do next. If you don't have SSH access at all, there's a new section pointing toward your hosting panel's IP blocker instead.</p>

            <h3>3.3.0 — 2026-04-18</h3>
            <p>Wondered how people are using the free reports. Added some additional tracking &mdash; and disclosed it all in the <a href="/privacy.php">privacy policy</a> &mdash; so I can see if there are ways to make it better.</p>

            <h3>3.2.1 — 2026-04-13</h3>
            <p>Squashed a bug in Umami event tracking.</p>

            <h3>3.2.0 — 2026-04-12</h3>
            <p>The paywall moved. Paste your IPs, get a free geo and ASN breakdown of your top 25 &mdash; shareable link, no account, no payment. It expires in 7 days, which is probably long enough to do something about the IPs in it. If you want AbuseIPDB confidence scores for the worst offenders, ready-to-run firewall scripts, and a permanent link, that's still $9. Speaking of permanent: paid reports no longer expire. The 30-day window is gone. You paid for it, it's yours.</p>

            <h3>3.1.4 — 2026-04-10</h3>
            <p>Squished some bugs. The kind that mostly just lurk &mdash; a concurrency edge case where Stripe could trigger two report generations at once, a quota guard to stop the seed script draining the AbuseIPDB daily allowance, a couple of small security tightenings. Nothing you would have noticed, and now you won't have to.</p>

            <h3>3.1.3 — 2026-04-04</h3>
            <p>Security audit follow-up. No bad guys found but, just in case: report tokens are now cryptographically random, classification data is recomputed server-side instead of trusted from the browser, and a timezone misconfiguration that sometimes made fresh reports appear expired has been corrected.</p>

            <h3>3.1.2 — 2026-04-03</h3>
            <p>A few small tweaks and bugfixes. That last polish with your sleeve before guests come over.</p>

            <h3>3.1.0 — 2026-04-03</h3>
            <p>A rolling 7-day <a href="/intel.php">Community Block List</a> built from opted-in Threat Reports. CIDR ranges corroborated by three or more independent users &mdash; filtered by prefix size and hit density so coarse ISP blocks don't slip through &mdash; appear on the public list, downloadable as iptables, ufw, nginx, or plain CIDR format.</p>

            <h3>3.0.0 — 2026-04-02</h3>
            <p>Threat Reports: paste a batch of IPs from your server logs, pay once, and get back a verdict (clean, watchlist, or threat), AbuseIPDB scores for the worst offenders, and ASN CIDR ranges so you can block whole subnets instead of individual addresses. Ready-to-run block scripts for iptables, ufw, and nginx download directly from the report. Reports are token-tied and expire after 30 days.</p>

            <h3>2.6.3 — 2026-03-23</h3>
            <p>Swapped Google Analytics for <a href="https://umami.is/" target="_blank" rel="noopener">Umami</a>. Same lookup and CSV download events are tracked, same visitor stats &mdash; just without sending your data to Google first. Umami is open-source and privacy-friendly, which feels more in keeping with a tool that doesn't log IPs.</p>

            <h3>2.6.2 — 2026-03-13</h3>
            <p>Removed the PayPal donation button. Coffee is better anyway, and PayPal's UX is bad.</p>

            <h3>2.6.1 — 2026-03-13</h3>
            <p>Housekeeping ahead of open-sourcing the repo:</p>
            <ul>
                <li>Added defensive HTML escaping.</li>
                <li>Tidied internal server references out of CI workflow comments.</li>
                <li>Removed a dead Google Universal Analytics snippet still haunting a couple of pages.</li>
                <li>Fixed testing tools to use <code>random_int()</code> so generated test IPs actually cover the full IPv4 address space.</li>
            </ul>

            <h3>2.6.0 — 2026-03-13</h3>
            <p>The IP lookup engine got a meaningful tune-up, cutting per-IP database time by about 60%. That cuts a 10,000-IP lookup from roughly 4.5 seconds of database time down to under 2. The site also now fires two Google Analytics events for CSV downloads and <code>ip_count</code>, so there's finally a wee little data on how ip2geo is being used being collected. (All of which is still blocked by ad blocker extensions or your friendly neighborhood <a href="https://pi-hole.net/" target="_blank" rel="noopener">pi-hole</a>.)</p>

            <h3>2.5.1 — 2026-03-13</h3>
            <p>Historical cruft cleanup.</p>

            <h3>2.5.0 — 2026-03-13</h3>
            <p>Submitting a large batch of IPs used to mean staring at a blank page for several seconds. No more. The form now submits via AJAX and a full-viewport loading overlay appears immediately showing how many IPs are being processed and stays visible until results are ready. The overlay falls back gracefully to a normal form submit if JavaScript isn't available. Page load transitions are also faster site-wide.</p>

            <h3>2.4.0 — 2026-03-12</h3>
            <p>Two releases in one day. We're on a roll. Results are now exportable: a Download CSV button appears above the table after any lookup, generating a properly-quoted RFC 4180 file client-side with no second round-trip to the server. IPs that returned no geo data get their own toggleable section so they're out of the way but not silently discarded. The summary stats below results got a full makeover &mdash; monospace, column-aligned, and actually informative (submitted vs. matched vs. filtered vs. unresolved, all accounted for). Also quietly retired <code>about.php</code> and its legacy UA analytics snippet, which had no business still existing.</p>

            <h3>2.3.0 — 2026-03-12</h3>
            <p>Taught ip2geo.org to update its own data. MaxMind's GeoLite2-City database now refreshes automatically on the first of every month: downloaded, converted, imported into shadow tables, verified against a known IP, then swapped in atomically while the old data keeps serving. If anything looks off, it rolls back and files a strongly-worded GitHub Actions failure notification. Also added a data freshness date to the footer, because it turns out people care how old their geolocation data is.</p>

            <h3>2.2.0 — 2026-03-11</h3>
            <p>Security hardening and grown-up deployment infrastructure. Fixed a handful of XSS vectors (nothing to see here), added a 2MB input cap, and corrected a bug that was silently discarding the <em>first</em> batch of IPs instead of the last. The old versioned index files are gone and git is the version history now, as it was always meant to be. Also introduced a full CI/CD pipeline with a staging environment, because apparently this is a serious project.</p>

            <h3>2.1.1 — 2025-04-05</h3>
            <p>Bugfix. Introduction of Changelog. Removed defunct twitter link. Made "About" section slightly more professional (slightly).</p>

            <h3>2.1.0 — 2025-04-04</h3>
            <p>Refactor database query approach. ~12% speed improvement through preconverting IPv4 addresses and avoiding INET6_ATON.</p>

            <h3>2.0.7 — 2025-04-04</h3>
            <p>Maxmind database update (2025-04-01).</p>
        </div>
    </div>
</section>
<?php render_page_close(); ?>
