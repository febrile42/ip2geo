# ip2geo — TODOs, Deferred Items & Open Questions

Last updated: 2026-04-02 (post-commit audit).
Source of truth for what's done, what's next, and what's deferred.

Plans live in: `~/.gstack/projects/febrile42-ip2geo/`
- `ceo-plans/2026-04-02-report-perceived-value.md` — report UX improvements (narrative, AbuseIPDB callout, CTA copy, effort-saved, checklist, print/share)
- `ceo-plans/2026-03-28-incident-triage-tool.md` — Phase C+A+B architecture, Stripe flow, verdict logic, test strategy
- `shadows-develop-design-20260328-220913.md` — full design spec (layout, interaction states, copy, a11y, responsive)
- `designs/design-audit-20260329/` — screenshots from design audit
- `QUESTIONS.md` (project root) — async design questions requiring owner input

---

## Current Phase State (as of 2026-03-29)

Phase A is built and deployed to staging. Revenue-gating is live behind Stripe Checkout.

**Done:**
- [x] ASN lookup per IP in geo results (second query per IP)
- [x] `asn_classification.php` — known_asns array + keyword fallback + Tor exit ASNs
- [x] report.php — token lifecycle, verdict, top-25 table, AbuseIPDB enrichment
- [x] Block script downloads (iptables, ufw) — all scanning/VPN IPs sorted by freq
- [x] Freq/hits column in report table
- [x] ASN CIDR ranges section in report (from geoip2_asn_current_int)
- [x] View all IPs (/?view_token=TOKEN) with back-to-report link
- [x] CSV download respects active filters (row-hidden check)
- [x] Scroll-to-results on form submit and view_token page load
- [x] Demo report (DEMO_TOKEN = 00000000-0000-0000-0000-000000000000)
- [x] Demo banner, expiry suppression, "See a sample report" link
- [x] Stripe webhook handler, payment confirmation, token lifecycle
- [x] AbuseIPDB cache, daily quota tracking, graceful degradation
- [x] report_functions.php (pure functions, unit-testable)
- [x] QUESTIONS.md for async design review

**Not yet built (pre-launch):**
- [x] Spamhaus ASN-DROP diff step in update-db.yml GitHub Actions workflow
- [x] Cancel URL flow (/?cancelled=1 → repopulate textarea)
- [x] Umami custom events (form submit with IP count bucket; export button clicks; report_view, report_download, report_tab_switch, report_copy_link, report_view_all_ips)
- [x] PHPUnit tests (VerdictAlgorithmTest, TokenLifecycleTest, WebhookHandlerTest, AbuseIPDBRankingTest, AsnClassificationTest, CacheTest) — 95 tests, 119 assertions
- [x] WCAG AA contrast check on verdict badge colors (#e06c9f, #e0a85a, #6cb87a) — all pass on #312450 body bg (4.55, 6.62, 5.85); CTA button (#111 on color) also passes (6.13, 8.92, 7.89). Print CSS overrides to black. HIGH is borderline at 4.55 but verdict text is large+bold (3:1 threshold applies).
- [ ] Investigate Umami Event properties page error (see item 6 below)
- [ ] QA agent doc (see item 7 below)
- [x] Report layout: move ranges and block rules above top threat sources (2026-03-30)
- [x] Block script downloads for ASN ranges + nginx format + tabbed button UX (2026-03-30)
- [x] Report print/PDF stylesheet (2026-03-30) — deployed, needs design review
- [x] 66/33 two-column grid: ASN Ranges left, Block Rules right with stacked buttons (2026-03-30)
- [x] Block rules tab labels: white-space:nowrap to prevent orphaned wrap (2026-03-30)
- [x] Button text vertical centering at all viewport sizes (2026-03-30)

---

## Near-Term TODOs (clear next actions)

### 1. Report layout: move ranges and block rules above top threat sources

The ASN Ranges and Block Rules sections are currently below the top-25 table.
They should come first — the table is supporting evidence; the actionable output
(ranges to block, scripts to download) is what the user came for.

New order in render_report():
  1. Demo banner (if applicable)
  2. Verdict badge + verdict text
  3. ASN Ranges to Block
  4. Block Rules (script download buttons)
  5. Top Threat Sources table (supporting detail)
  6. Share/expiry/view-all links

---

### 2. Block script downloads for ASN ranges + nginx format + button UX

**What to add:**
- `block-iptables-ranges.sh` — iptables DROP rules using CIDR ranges from `asn_ranges`
- `block-ufw-ranges.sh` — ufw deny rules using CIDR ranges
- `block-nginx.conf` — nginx geo block using individual IPs from `block_ips`
  (nginx geo module uses IP/CIDR entries, not shell commands — different format)
- Optionally: `block-nginx-ranges.conf` — nginx geo block using ASN CIDR ranges

**Button proliferation problem:**
Currently 2 buttons. Adding range-based + nginx = 4–6 buttons. Consider:
- Option A: tabbed selector ("Block by IP" | "Block by Range") with format sub-buttons per tab
- Option B: dropdown per format type (iptables ▾ → [by IP] [by range])
- Option C: two primary buttons (IPs / Ranges) each expanding to format options inline
- Recommendation: Option A (tabs) — cleanest, scannable, familiar pattern

Note: range-based scripts are more resilient (ranges stay valid as IPs rotate) but may over-block
if ASN includes legitimate cloud traffic mixed with scanning exit nodes.

---

### 3. Report print/PDF layout

Plan a print stylesheet (`@media print`) that produces a clean, un-styled export suitable
for attaching to an incident ticket.

Design goals:
- Strip sidebar, nav, dark background, Hyperspace chrome
- White background, black text, readable monospace tables
- Verdict badge readable without color (add parenthetical: "HIGH THREAT (scanning: 75%)")
- CIDR ranges and block script previews render as plain text blocks
- Page header: "ip2geo Threat Report — [date] — [N] IPs analyzed"
- Remove interactive elements (buttons, copy links) or replace with static text equivalents
  e.g. "Download at: https://ip2geo.org/report.php?token=..." as plain text

Implementation: a `<link rel="stylesheet" href="/assets/css/ip2geo-print.css" media="print">`
that overrides the base + Hyperspace styles. No JavaScript needed.

---

### 4. Filter split: free vs. paid

**Current state:** The free page (index.php) has full category + country filter with live
firewall rule preview. This is arguably the most powerful part of the product.

**Plan:**
- Free (keep forever): category chips + country chips filtering the table, live row count
- Free (keep): basic CSV download of current filter
- Move to paid / enhance in paid: full filter persistence, filter-then-generate-report,
  multi-select rule export across filter states

Open question first (see QUESTIONS.md #1): decide whether the free filter IS the product
or a gateway to the paid report. These require different UX decisions.

Short-term: no changes to free filter. Make note that the filter UX in report.php (view_token
mode) currently has no way to regenerate block scripts from a filtered subset. That's the
gap that a paid filter feature would close.

---

### 5. Collapse the IP wall of text

**Two motivations:**

A. **Paid report usability:** right now the "View all IPs" link re-runs the full geo lookup,
which is 2–4s for 10K-IP batches and returns a raw table. A user mid-incident wants
a filtered, prioritized view — not 10,000 rows.

Plan: store `geo_results_json` in the reports row at generation time (same pass as
`report_json`). The view_token page serves this instead of re-running queries.
Trade-off: ~600KB additional DB storage per row. Acceptable — MEDIUMTEXT limit is 16MB.
Also solves QUESTIONS.md #3 (re-query cost).

B. **AI context efficiency (Phase B):** when we add Claude API analysis, we need to send
a compact representation of the IP list — not raw IPs, not 10K-row JSON.
Target structure: per-ASN aggregates with freq totals, top offenders, category distribution.
~2–5KB of structured text vs. ~600KB raw JSON. Compressing at storage time makes
the Phase B API call cheap and the prompt predictable.

Design the schema now even if Phase B isn't built yet:
- `geo_results_json` — full per-IP lookup results, stored at generation time
- `summary_json` — compact aggregate (ASN → count, category → count, top-10 IPs by freq)
  Used by Phase B prompt. Could also power a richer free-tier summary.

---

### 6. Investigate Umami Event properties page error

Umami is firing custom events (form submit, export, report_view, etc.) but the Event properties
page in the Umami dashboard is returning an error. Investigate before relying on event data
to answer Q6 (visitor intent: incident response vs. curiosity).

Steps:
- Log into Umami, navigate to Events → Event properties
- Capture the error message
- Check whether the issue is a Umami version bug, a misconfigured event payload, or a data volume issue
- Verify raw event counts look sane (Events tab, not properties)

---

### 7. QA agent doc

Write a doc that a Claude Code QA agent can use to verify everything end-to-end,
without needing Stripe credentials or context on how the code works.

Contents:
- Demo report URL + token (DEMO_TOKEN = 00000000-0000-0000-0000-000000000000)
- Demo "view all IPs" URL
- What to check on each page (verdict, table columns, section order, button labels)
- Filter behavior to verify (category chips hide rows, CSV respects filter, count updates)
- Block script format to verify (shebang, IP count in comment, one rule per line)
- ASN ranges format to verify (CIDR notation, correct ASN/org label, range count)
- Scroll-to-results behavior (form submit AND view_token page load)
- Buttons to test: iptables download, ufw download, Copy report link, View all IPs,
  Back to your report, New Lookup, See a sample report
- What NOT to test: anything requiring Stripe (payment flow, token generation)
- Known staging URL: staging.ip2geo.org

---

## Open Questions (requiring owner input)

These are product/design decisions that need a call before implementation.
Full context in `QUESTIONS.md`.

### Q1 — Shell script content: paid vs. free — RESOLVED 2026-04-02
Paid report now has category filters + Block by IP + Block by Range tabs. Parity with free page achieved. Closed.

### Q2 — Frequency data on free page — RESOLVED 2026-04-02
Freq stays paid-only. Intentional differentiator.

### Q3 — View all IPs performance — RESOLVED
`geo_results_json` column added, stored at generation time, nulled on redemption. No re-query. (commits f5666a5, 57c7e84)

### Q4 — Country filter carry-through — WONTDO
"Show all, filter client-side" is the right default. Not worth storing original filter state.

### Q5 — Report expiry model — RESOLVED 2026-04-02
30-day expiry is correct. view_token tied to same token is fine. Cleanup cron handles expiry.

### Q6 — Visitor intent (from CEO plan)
Umami Event properties page is erroring — investigate before relying on event data. See near-term TODO below.

### Q7 — Programmatic access check — WONTDO
Not worth the investigation at Phase A scale. Revisit if API monetization becomes a priority.

### Q8 — asn_org not stored in ip_list_json for real paid reports — RESOLVED 2026-03-30
Added `'asn_org' => $asn_org` to `$ip_classified_data` in `index.php:244`. Forward fix only — existing DB rows not back-filled.

---

---

## Stripe Account Activation — Required Before Production Launch

Stripe reviews the live site for compliance before activating the account for payments.
Contact email: **support@ip2geo.org**

- [x] **Add contact email to index.php and footer** — `support@ip2geo.org` added to footer (commit 7ae6172)
- [x] **Update privacy.php** — updated for v3.0.0: Stripe, DB retention, AbuseIPDB all covered (commit 7ae6172)
- [x] **Create legal.php** — refund/cancellation/dispute policies live (commit 3c5ebb6)
- [x] **Describe the paid product publicly** — "Full Threat Reports" section added to index.php with pricing and what's included (commit 083d54a)
- [x] **Add Legal / Refund Policy link to footer** — "Refund Policy" link in footer alongside Privacy Policy (commit 3c5ebb6)

---

## Post-Phase A: Report Engagement (defer until 10+ real purchases)

### Repeat-purchase CTA at report bottom
**What:** Add one line at the bottom of the paid report: "Responding to a new incident? Analyze another batch →" linking to ip2geo.org.
**Why:** The buyer who just got value is the most likely next buyer. The report currently ends with nothing — buyer closes the tab.
**Pros:** Lowest-effort repeat-purchase signal. Landing point for Phase D "$3 re-analyze" upsell.
**Cons:** Needs purchase data to validate whether buyers actually return. May feel premature before Phase A launches.
**Context:** From 2026-04-02 CEO review. ~3min CC effort. Wait until Phase A has 10+ real purchases.
**Effort:** S | **Priority:** P2 | **Depends on:** Phase A revenue validation

### Email delivery for paid report
**DONE** — Shipped via Resend. Report link emailed automatically after payment (webhook triggers send). Resend link shown on report page if buyer needs it re-sent. Implementation: `send-report-link.php` + `includes/email_helper.php`. Different from original plan (user-triggered form) — automatic delivery is better UX. (commits 44b0e1a, 8d0c43b, 170a285)

---

## Deferred — Phase B

- AI-powered threat report (Claude API) — replaces rule-based verdict
- Email notification field UI (`reports.notification_email` column already exists)
- Phase B pricing decision: per-report vs. subscription (defer until Phase A validates demand)
- Animated verdict reveal effects (only if Phase B revenue justifies polish)

---

## Deferred — Phase D

- World map SVG choropleth (countries colored by IP count)
- Log format detection (fail2ban / sshd / nginx / Apache auto-parse)
- "Re-analyze for $3" upsell on report page (only if Phase A shows repeat purchase friction)

---

## Deferred — Infrastructure / Maintenance

### Spamhaus ASN-DROP workflow (ships before Phase A production launch)
Monthly update-db.yml step: curl Spamhaus ASN-DROP, diff against asn_classification.php,
open draft PR with proposed additions. Never auto-merged. See CEO plan for bash sketch.

### Expired report cleanup job
**DONE** — Cleanup script created and deployed for cron on lime (commit 6d7502a). `geo_results_json` nulled on redemption to reclaim space (commit 57c7e84). At ~2.6 MB/paid report effective storage, disk ceiling is ~3,200 paid rows on 8.5 GB free.

---

## Tests — Built

All PHPUnit tests built (8 files, 95+ tests):
- [x] `tests/VerdictAlgorithmTest.php`
- [x] `tests/TokenLifecycleTest.php`
- [x] `tests/WebhookHandlerTest.php`
- [x] `tests/AbuseIPDBRankingTest.php`
- [x] `tests/CacheTest.php`
- [x] `tests/AsnClassificationTest.php`
- [x] `tests/ReportFunctionsTest.php`
- [x] `tests/EmailHelperTest.php` (added beyond original plan)

Pre-launch manual Stripe test protocol (from CEO plan) — run before any production traffic.
