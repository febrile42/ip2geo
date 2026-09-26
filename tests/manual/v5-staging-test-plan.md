# v5.0.0 staging test plan

Source: `HANDOFF.md` on `v5` (snapshot 2026-09-25). Target: https://staging.ip2geo.org (branch `v5`).
The owner's own test plan and mockups live only on their machine (`~/.gstack/...`); this plan
is derived from HANDOFF and the public repo only. Ask Sunraku if the owner's plan would add
coverage this one is missing.

Environments to repeat the applicable sections in:

- Desktop, JS on, Chromium (primary), latest Firefox/Safari spot-check.
- 390 px mobile emulation (iPhone 12/13 width), JS on.
- No-JS (JS disabled), desktop width.
- A physical phone (see the short checklist at the end) — HANDOFF section 8 notes this has
  never been done; Playwright's Pixel 7 emulation is not a substitute.

For every run, record: URL, viewport, JS on/off, and the footer version string
(`curl -s https://staging.ip2geo.org/ | grep -o 'v[0-9.]*' | head -1`, expect `v5.0.0`).

## 1. Core lookup (JS workbench)

1. Load `/`, paste a small synthetic log mixing IPv4 and IPv6 addresses (documentation ranges:
   `192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`; plus the built-in Censys/Spamhaus sample).
   Expect: results table renders client-side, one POST to `/api/lookup.php`, plain-English
   summary line above the table with correct counts.
2. Click "Try a sample log". Expect: it includes the visitor's own IP, and the log deep-dive works.
3. Confirm IPv6 rows resolve to real geo/ASN data (not "Unknown") — v5's MaxMind move is meant to
   add real IPv6 lookup.
4. Toggle "show unresolved IPs". Expect: unresolved rows appear/hide, count matches summary.
5. Check the lookup timer shows a realistic non-zero value (regression: previously always showed 0.0 s).

## 2. Filters and analytics (D9)

1. Apply a country filter chip, a category filter chip, and use the search box.
2. In the browser network tab / Umami, confirm each fires `filter_<dim>` (`filter_country`,
   `filter_category`, `filter_search` etc.) with **only the dimension**, never the filter value,
   per `umami-events.md` D9. This was the "known gap" in HANDOFF section 8 (commit 5b6b1f8) —
   verify it actually fires now that it's supposedly built.

## 3. Exports

For each format, trigger the export menu and verify content matches the filtered result set:

- TSV
- CSV
- KQL (Kibana Query Language)
- SPL (Splunk)
- iptables
- ufw
- nginx (deny/allow rules)

Expect: each export reflects only currently-filtered rows, uses IPs (not resolved values) where
that's the intent, and downloads/copies without a JS error.

## 4. Share links (`#v=`)

1. Apply filters, copy the share link.
2. Open the link in a fresh tab/private window. Expect: the same filtered view restores from the
   `#v=` fragment, no extra network round-trip to the server for state.
3. Confirm the fragment is stripped before any analytics tracker fires (R3 — privacy).

## 5. DROP explainers

1. Desktop: hover a DROP label in the table. Expect: tooltip with the Spamhaus DROP explanation.
2. Desktop: hover DROP mention in the summary line. Same explanation text (PHP/JS parity is
   enforced by `tests/DropExplainerTest.php` — a visual mismatch here is a real bug).
3. Mobile (390 px) and physical phone: tap the DROP label. Expect: a popover (not a hover tooltip,
   which never shows on touch) with the same explanation text.

## 6. No-JS fallback

1. Disable JavaScript, load `/`, submit the paste form.
2. Expect: `render_lookup_results()` renders the results table server-side, including the summary
   line and a DROP explanation reachable without JS (check `index.php`'s no-JS DROP path).
3. Confirm no console/network errors are needed for this path to work end-to-end.
4. Confirm Cloudflare Rocket Loader doesn't matter here (no JS to reorder).

## 7. Mobile layout (390 px)

1. Scroll the results table sideways. Expect: the IP column stays pinned (sticky), readable over
   both `#results-table` and `#wb-results-table`.
2. Check striped (odd/even) rows under the pinned column: the pinned cell background must be
   opaque (gradient over `--surface`), not a transparent rgba showing the row behind it.
3. Confirm the sticky table header sits at `top: 0` inside the scroll wrapper and does not cover
   the first data row (regression: it used to sit at `top: 56px`).
4. Check the mobile toolbar (Export / Copy share link) stacks instead of wrapping awkwardly.

## 8. Rocket Loader

Cloudflare Rocket Loader is on for the zone and rewrites/reorders `<script>` tags unless they opt
out.

1. View source on the live staging page; confirm every `<script>` tag carries
   `data-cfasync="false"`.
2. With Rocket Loader active (default, don't disable it — this must pass as deployed), confirm the
   workbench still initializes and lookups still work. This previously broke silently on staging.

## 9. Error / limit responses

Use synthetic data only; no real user data or abuse-scale load.

1. **413** — POST a payload over the documented cap (10,000 IPs, or 2 MB, whichever is easier to
   construct) to `/api/lookup.php`. Expect: HTTP 413, no partial processing.
2. **429** — send just over 60 requests/minute from one IP to `/api/lookup.php` (APCu-backed).
   Expect: HTTP 429 once the limit is crossed, and that normal service resumes after the window.
   Do not sustain this beyond confirming the one transition.
3. **503** — HANDOFF says this fires "when data is missing" (i.e. `.mmdb` files absent/unreadable).
   This is not safely reproducible against shared staging without risking an outage for other
   testers; verify by code inspection (`includes/lookup.php` / `api/lookup.php` error path) instead
   of by disabling staging's GeoIP data. Flag to Oikatzo only if the code path looks untested.
4. **403 on `/data/geoip`** — request `https://staging.ip2geo.org/data/geoip/` and any known file
   under it directly. Expect: HTTP 403 (the GeoLite2 license requires this directory never be
   web-reachable; CI is supposed to assert it already).

## 10. Retired paid tier

1. Confirm `/report.php` returns 410.
2. Confirm no UI path references Threat Reports, Stripe, Resend or AbuseIPDB.

## 11. Accessibility spot-check

1. Run an axe scan (or reuse the Playwright a11y spec) against `/` with results loaded.
2. Specifically re-check the "Save recent lookups" toggle contrast (regression fixed pre-v5) and
   the DROP popover's focus/dismiss behaviour on keyboard and touch.

## Out of scope for this pass

- Server-side release steps, crons, keys, Stripe, the retirement migration (owner-only).
- Production (`ip2geo.org`) — this plan targets staging only.
- Sustained load/abuse testing beyond the single-request checks in section 9.

---

## Physical-phone checklist (for the owner)

A short pass on a real phone, since HANDOFF section 8 notes this has never been done (only
Playwright's Pixel 7 emulation). Takes about 10 minutes:

1. Open https://staging.ip2geo.org on your phone's normal browser (not desktop mode).
2. Paste or tap "Try a sample log" — do results load and does the summary line read correctly?
3. Scroll the results table sideways with your thumb — does the IP column stay pinned and stay
   readable (not see-through) over striped rows?
4. Tap a DROP label — does a popover open (not nothing, not a tooltip that won't dismiss)? Tap
   elsewhere — does it close?
5. Try the export menu and "copy share link" — do they work with one thumb, without the toolbar
   buttons wrapping oddly?
6. Reload the copied share link in a new tab — does it come back filtered the same way?
7. Rotate to landscape once — does anything clip or overlap?

Anything that looks wrong: a screenshot plus which step is enough to file it back.
