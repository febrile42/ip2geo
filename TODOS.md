# ip2geo — TODOs, Deferred Items & Open Questions

Last updated: 2026-04-03 (Phase C go-live checklist updated; staging schema migration done).
Source of truth for what's done, what's next, and what's deferred.

Plans live in: `~/.gstack/projects/febrile42-ip2geo/`
- `ceo-plans/2026-04-02-community-intel-flywheel.md` — **ACTIVE** Phase C: community CIDR/IP aggregate, /intel.php, consent flow
- `ceo-plans/2026-04-02-report-perceived-value.md` — report UX improvements (narrative, AbuseIPDB callout, CTA copy, effort-saved, checklist, print/share)
- `ceo-plans/2026-03-28-incident-triage-tool.md` — Phase C+A+B architecture, Stripe flow, verdict logic, test strategy
- `shadows-develop-design-20260328-220913.md` — full design spec (layout, interaction states, copy, a11y, responsive)
- `designs/design-audit-20260329/` — screenshots from design audit

---

## Current Phase State (as of 2026-04-02)

**v3.0.0 tagged** — Phase A complete, deployed to staging, QA clean (97/100).
Stripe account under review; payments not yet live. Tagged `v3.0.0` on develop.
Phase C (community intel flywheel) now in active development on develop branch.

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
- [x] QA agent doc (see item 6 below)
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

### 6. QA agent doc — DONE 2026-04-02

`QA.md` created in project root. Covers all 7 public pages, demo token, DO NOT TEST
list (Stripe, webhook, email), filter/CSV/firewall rule behavior, block script format,
scroll behavior, and known headless limitations.

**Clean pass run 2026-04-02:** All 7 pages HTTP 200, 0 console errors. One bug found
and fixed: privacy.php omitted AbuseIPDB as a third-party data processor (ISSUE-001,
commit a813261). Re-verified on staging post-fix — health score 97/100.

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

### Q6 — Visitor intent (from CEO plan) — RESOLVED 2026-04-02
Umami Event properties page error was a known Umami Cloud UI bug, not a data issue. Raw event counts are sane. Check Events tab directly for visitor intent data.

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

## Phase C: Community Threat Intelligence Flywheel

Full spec: `~/.gstack/projects/febrile42-ip2geo/ceo-plans/2026-04-02-community-intel-flywheel.md`

**What it is:** Opted-in reports contribute anonymized CIDR ranges and scanning/VPN IPs
to a community aggregate. Powers a public weekly block list (/intel.php) and a "community
context" column in paid reports ("this IP hit 31 other servers this week, escalating ↑").

**Data collected (with consent only):**
- CIDRs from `report_json['asn_ranges'][].cidrs[]`
- IPs from `ip_list_json` where `classification IN ('scanning', 'vpn_proxy', 'cloud_exit')`
- Residential IPs: **never collected, never stored.**
- No token, email, or user identifier in aggregate tables.

**Implementation order:**

- [x] `scripts/migrate-community.sql` — 3 new tables + ALTER reports (commit 18d9704)
- [x] `privacy.php` — Community Threat Intelligence section added (commit 5f743d4)
- [x] `community-consent.php` — POST-only AJAX endpoint (commit 18d9704)
- [x] `report.php` — consent banner + community column + fetch_community_data() (commit 5f743d4)
- [x] `intel.php` — public block list, 4 download formats, threshold guard, CTAs (commit 5f743d4)
- [x] `sitemap.xml` — /intel.php added (commit 5f743d4)
- [x] `QA.md` — consent flow + community column + /intel.php sections added (commit 5f743d4)
- [x] `update-db.yml` — 52-week retention DELETE step added (commit 5f743d4)
- [x] `tests/CommunityConsentTest.php` — 37 tests, 63 assertions (commit 5f743d4)

**Phase C complete. Run `/qa` against staging before merging to main.**

**Must-do before go-live (community intel):**
- [x] **Schema migration on ip2geo_staging** — `ALTER TABLE` (week_start → report_date) + `CREATE TABLE community_weekly_stats` run on staging (2026-04-03). Confirmed working: 6 opted-in reports showing on staging.
- [x] **Schema migration on prod** — ALTER TABLE (week_start → report_date) + CREATE TABLE community_weekly_stats run on `ip2geo` prod DB (2026-04-03).
- [x] **Clear community stats tables** — all 4 community tables truncated on prod (2026-04-03).
- [x] **Staging DB isolation** — `ip2geo_staging` schema created, full schema copied (including static lookup tables), schema migration (week_start → report_date + community_weekly_stats) complete. `config-staging.php` updated to `$db_name = 'ip2geo_staging'` (2026-04-03).
- [ ] **Monthly update workflow** — after staging DB isolation, update `.github/workflows/update-db.yml` to also update `ip2geo_staging` DB (MaxMind + AbuseIPDB) to prevent drift.
- [x] **Caching on intel.php** — APCu page-level cache added (15-min TTL, key `intel_page_7d_{date}` auto-invalidates at UTC midnight; downloads bypass; graceful fallback if APCu unavailable). (2026-04-03)
- [x] **Fix CommunityConsentTest.php** — updated to `report_date`, `community_weekly_stats` added to setUp, rolling date logic updated. 37/37 tests passing (2026-04-03).

**Revisit gate:** Once 50+ opted-in reports exist, re-evaluate beta thresholds, framing,
and whether community column needs a total reframe. Log findings.

**Deferred from this phase:**
- API access for community data (Phase C.5 — after flywheel proves value)
- Weekly email digest to opted-in users (Resend already integrated; defer until data is meaningful)
- Historical trend sparklines on /intel.php (data already in weekly buckets; UI deferred)
- Week-over-week trend indicator in community column on report.php — data is already stored (`last_week` queried alongside `this_week` in `fetch_community_data`). Deferred because ↑/→/↓ arrows are ambiguous at low report counts and the dataset is too small to make trend signals trustworthy. Revisit once 50+ opted-in reports establish a baseline: consider `<abbr>` tooltip or short text label ("rising"/"stable"/"falling") rather than bare arrows.
- Firewall automation daemon (Phase D — after API is established)
- CIDR hit counts in community data — `total_hits` ingestion now computes real per-CIDR hit sums via `ip_in_cidr()` at opt-in time (shipped 2026-04-03). Display still omits `total_hits` from the UI — add it back to `intel.php` table and the opt-in banner in `report.php` once there's enough data to make it meaningful (revisit at 50+ opted-in reports).

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

## Deferred — AbuseIPDB Block Check enrichment

**What:** Use `/api/v2/check-block` to score CIDR ranges in the ASN Ranges section. Shows "74% of IPs in this range have AbuseIPDB reports" alongside each CIDR — stronger recommendation signal than classification alone.
**Why deferred:** Free tier is 100 block checks/day. A typical HIGH-verdict report uses 15–30 checks (2–3 ASNs × 5–10 ranges). Quota exhausts at 3–6 paid reports/day — too tight for production.
**When to revisit:** Once on a paid AbuseIPDB plan with higher block check limits.
**Effort:** M | **Priority:** P3 | **Depends on:** AbuseIPDB paid plan

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

## Investigate — Performance

### DB index / storage optimizations
**What to investigate:** Are there schema-level wins we haven't taken yet? Known candidate:
- `abuseipdb_cache.ip` is stored as `VARCHAR` — converting to `VARBINARY(16)` (packed `INET6_ATON()`) would halve the index size for that table and speed up point lookups. Need to audit all IP-storing columns across all tables (reports, community_ip_stats, community_ip_first_seen, community_cidr_stats) for the same pattern.
- Check for missing composite indexes on columns used together in WHERE + GROUP BY (e.g. community tables queried on `report_date` + `ip`/`cidr`).
- Check whether `geoip2_asn_current_int` range lookups are using the int-pair index correctly (EXPLAIN on a sample lookup).

**Why:** At low traffic this is invisible. At scale (community flywheel + many paid reports) a poor index on a hot lookup path will show up fast. Cheap to fix early.
**When:** Before or alongside Phase C go-live. One-session audit + migration.
**Effort:** S–M | **Priority:** P2

---

## Investigate — Email Reputation

### DMARC reports show mail "from" google.com — RESOLVED 2026-04-03
**Root cause:** Benign forwarding artifact. A recipient forwarded a Resend-sent ip2geo.org email via Gmail. Google's mail servers appeared as the source IP; envelope-from rewrote to gmail.com (SPF aligned: fail), but the original ip2geo.org DKIM signature survived intact (DKIM aligned: pass), so DMARC passed overall. No spoofing, no misconfiguration.

**Action taken:** DMARC policy hardened from `p=none` → `p=quarantine`, `sp=quarantine`, `fo=0`. Record confirmed in DNS (2026-04-03). Monitor DMARCLY for 1–2 weeks, then move to `p=reject`.

---

## Deferred — Infrastructure / Maintenance

### config.php file permissions — LOW PRIORITY
**What:** `config.php` (and `config-staging.php`) must be readable by the web server process (e.g. `www-data`). If permissions are set to `700`, the file is only readable by the owner, causing PHP to 500 as soon as the in-memory cached file handle is released.
**Correct permissions:** `744` (owner rwx, group+world read). Or `640` with the web server user in the owner's group.
**History:** 2026-04-03 — permissions set to `700` on both staging and production, causing intermittent 500s during deploy. Reverted to `744` to restore. CI smoke test also false-positive'd during this window.
**Fix needed:** Add a deploy step that enforces `chmod 744 config.php` post-deploy, or document in DEPLOYMENT.md. Low priority.

### Spamhaus ASN-DROP workflow — DONE
Built and merged (febrile42/ip2geo#5). Monthly step in update-db.yml: fetches asndrop.json,
diffs against asn_classification.php, opens draft PR with candidates. Never auto-merged.

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
