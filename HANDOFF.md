# ip2geo v5: handoff

This is for someone (human or agent) picking up ip2geo.org with no prior context. The snapshot is as of **2026-09-25**. Verify anything time-sensitive before you act on it (branch heads, what's live).

**The one-line state:**

- v5.0.0 is feature-complete on the `v5` branch and deployed to **staging only**.
- Production still runs **v4.3.3**.
- Nothing more ships until the owner has QA'd staging and says "release".

---

## 1. What ip2geo is, and what v5 changes

ip2geo.org is a free bulk IP lookup. You paste logs and get country, city, ASN, a category and a Spamhaus DROP flag for every IP. It's aimed at people doing SOC and IT triage. The owner's goal is reputation and usefulness, not revenue:

> "a seriously fast, filter/data slice and dice, ip geo lookup … get cited and into that SOC/IT toolkit on merit alone."

v5.0.0 is one release that does all of this:

- **Retires the paid tier completely.** Threat Reports, Stripe, Resend and AbuseIPDB are gone, and `report.php` returns 410.
- **Moves lookups from MySQL integer ranges to MaxMind `.mmdb` files**, via `maxmind-db/reader` plus the `php-maxminddb` C extension. It adds real **IPv6** lookup, and a 10k-IP lookup takes about 0.2–0.5 s.
- **Adds a client-side "workbench"** (`assets/js/workbench.js`):
  - the paste is parsed in the browser
  - only the IPs are POSTed to `/api/lookup.php`
  - results are filtered, exported (TSV/CSV/KQL/SPL/iptables/ufw/nginx) and shared as `#v=` fragment links on the client
- **Keeps a no-JS fallback.** `index.php` still renders results on the server.
- **Adds:**
  - a plain-English summary line
  - a "Try a sample log" demo that includes the visitor's own IP
  - DROP explainers (hover plus tap popover)
  - mobile layout work (pinned IP column)
  - an accessibility pass
  - versioned asset URLs

Decisions that are settled, so don't reopen them without the owner:

- **Lookups stay on the server** with MaxMind data. "Local-only / ship the DB to the browser" was rejected: the database is hundreds of MB and has licensing limits.
- **Privacy is honest but not the headline differentiator.** Speed and usability are.
- **Cloudflare Pages/Workers are parked** as an investigation spike.
- **The simple text logo stays.**
- **The Community Block List is retired in v5.0.0** (IPG-7 option 2A). Its tables are kept for now; a DROP-based block list is post-release roadmap work.

## 2. Where everything is

| Thing | Location |
|---|---|
| Production | https://ip2geo.org: `main`, which is at `8676d46` (PR #56) and footer **v4.3.3** |
| Staging | https://staging.ip2geo.org: `v5`, which is at `78f017c` and footer **v5.0.0** |
| Rollback tag | `v4-final` → `8676d46` (the production commit before v5) |
| v5 work | branch `v5`, cut from `main`. It is 60 commits ahead and has **no PR yet** |
| Admin dashboard | private repo `febrile42/ip2geo-admin`, branch `feat/retire-report-sections` (v0.3.0.0). Pushed, no PR. It freezes the retired report sections and splits Reputation into Historical and Live |
| Server | one Debian 13 box (Apache + mod_php, PHP 8.4), `/var/www/ip2geo` (prod) and `/var/www/ip2geo-staging`, behind Cloudflare. Deploys run over SSH from GitHub Actions secrets |
| Analytics | self-hosted Umami. Events are documented in `umami-events.md` |

**Owner-only context** (not in this public repo; it's on the owner's workstation):

- **The full design doc**, with every decision R1–R17 and D1–D16, the evidence, and the release plan: `~/.gstack/projects/febrile42-ip2geo/shadows-main-design-20260922-231428.md`
- **Approved mockups:** `~/.gstack/projects/febrile42-ip2geo/designs/results-workbench-20260923/`
- **`DESIGN.md`** (the design tokens, derived from `assets/css/v4.css`, which wins on conflict) and **`TODOS.md`**: both are gitignored, so they exist only in the owner's checkouts. `TODOS.md` currently holds two items:
  - the Cloudflare spike
  - the Recent-lookups keep/remove decision

Section 7 repeats both.

## 3. Code map (v5)

| Path | Role |
|---|---|
| `index.php` | Page, form, no-JS `render_lookup_results()` (behind `handle_nojs_lookup()`'s rate limit: 429 over 60 POSTs/min/IP), and the workbench markup (`#workbench-root`) |
| `includes/extract.php` / `assets/js/extract-ips.js` | IP extraction. **They must stay behaviour-identical.** Both are locked to `tests/fixtures/extract` golden files |
| `includes/lookup.php` | `lookup_ips()`: the `.mmdb` reader, and `GEOIP_MMDB_DIR`, which defaults to `<app>/data/geoip`. It requires Composer's autoloader itself (see Gotchas) |
| `api/lookup.php` | JSON endpoint. Returns 413 over 10k IPs or 2 MB, 429 over 60 requests/min/IP (APCu), and 503 when data is missing. Request bodies are never logged |
| `includes/client-ip.php` / `includes/rate-limit.php` | Shared by both lookup paths: the client IP (CF-Connecting-IP only from a Cloudflare edge) and the APCu limiter. Separate buckets per path (`lookup_rate:` API, `lookup_rate_nojs:` no-JS). Fails open without APCu |
| `includes/summary.php` / `assets/js/summary.js` | Summary line. `DROP_EXPLAINER` text is duplicated in PHP and `workbench.js`, and `tests/DropExplainerTest.php` enforces parity |
| `assets/js/workbench.js` | Client render, the filters glue, exports, share links, the unresolved toggle and the lookup timer |
| `assets/js/filters.js`, `export-templates.js`, `share-link.js`, `abbr-popover.js` | UMD modules (`window.*` plus `module.exports` for Jest) |
| `assets/js/ip2geo-app.js` | Older v4 page JS: theme, Recent lookups, the server-table filters, firewall-rules panel |
| `assets/css/v4.css` | All styles. The mobile rules live in the `max-width: 767px` block |
| `includes/version.php` | `APP_VERSION` (5.0.0). Keep it equal to `VERSION`. Every asset URL uses `?v=<?= APP_VERSION ?>` |
| `asn_classification.php` | ASN → category map. The ASN-DROP auto-sync block is regenerated monthly |
| `spamhaus_drop_data.php` | Spamhaus DROP netblocks, regenerated weekly. It's a local list, with **no API and no quota** |
| `report.php`, `intel.php` | Static 410 "retired" pages (Threat Reports; Community Block List) |
| `migrations/retire_reports_v5.sql` | Manual, backup-first report-table retirement. **Not run yet** |
| `scripts/fetch-mmdb.sh` | Deploy-time `.mmdb` fetch: netrc auth, SHA256 check, 8.8.8.8 spot check, atomic swap, skipped if the files are less than 35 days old |
| `scripts/update-geoip.sh` | Monthly refresh (`.mmdb` plus legacy MySQL tables), run from `~/bin` on the server |
| `changelog.php` | Public changelog. The **5.0.0 entry is a DRAFT** for the owner to finalize, in their own first-person voice |
| `privacy.php` | Describes the JS path (the paste stays in the browser) and the no-JS path (text is sent, parsed and not stored). **Keep it exactly true** when behaviour changes |

## 4. Working on it

See README → Development for full commands. In short:

```bash
composer install && vendor/bin/phpunit      # 209 tests, 1 skipped
npm ci && npx jest                          # 210 tests
cp config.sample.php config.php && mkdir -p data/geoip \
  && cp tests/fixtures/mmdb/GeoIP2-City-Test.mmdb data/geoip/GeoLite2-City.mmdb \
  && cp tests/fixtures/mmdb/GeoLite2-ASN-Test.mmdb data/geoip/GeoLite2-ASN.mmdb
npx playwright test                         # 7 specs; php -S on :8935
```

**Deploying the `v5` branch to staging:**

```bash
gh workflow run deploy.yml --ref v5 -R febrile42/ip2geo
gh run watch -R febrile42/ip2geo   # lint → tests → deploy-staging → test-staging; production is skipped
```

After a deploy, read the footer version back from the live page:

```bash
curl -s https://staging.ip2geo.org/ | grep -o 'v[0-9.]*' | head -1
```

**Commit style on `v5`:** one declarative sentence about what a user now sees. For example, "On phones the workbench table keeps its IP column pinned while scrolling sideways…".

**Stage by explicit path. Never `git add -A`.** `config.php`, `data/geoip/` and `test-results/` sit in the tree, and they are ignored only by `.gitignore`.

## 5. Gotchas that each cost real time

1. **Cloudflare Rocket Loader is on for the zone and stays on for production.**
   - It rewrites `<script>` tags and reorders execution, which silently broke the workbench on staging.
   - Every script tag must carry `data-cfasync="false"`, and `tests/RocketLoaderOptOutTest.php` fails the build otherwise. Any new `<script>` needs it too.
2. **Composer autoload.** `includes/lookup.php` requires `vendor/autoload.php` itself.
   - PHPUnit's bootstrap loads the autoloader, which once hid the fact that the live page didn't. The result was a page that died right after the form, on staging only.
   - `tests/LookupAutoloadTest.php` checks this in a fresh PHP process.
3. **The Spamhaus syncs overwrite staging.**
   - The Monday DROP sync (and the monthly ASN-DROP sync on the 1st) commit to `develop`, deploy `develop` to staging, and **auto-promote `develop` → `main`** when the delta is only their data file.
   - So:
     - (a) **never merge `v5` into `develop` before release day**, or the bot ships v5 to production
     - (b) **re-dispatch the v5 staging deploy after every sync**, or staging is showing v4
4. **Asset caching.** Cloudflare caches `/assets/*` for 24 h, so bump `APP_VERSION`/`VERSION` for every release, or the new HTML gets paired with old JS. The Cloudflare API token on the owner's machine **can't purge cache**, because it lacks that permission.
5. **Line endings.** `.github/workflows/deploy.yml` and `update-db.yml` are **CRLF**. Edit them without normalizing, or the diff rewrites every line.
6. **Parity pairs.**
   - The extraction (PHP and JS) and `DROP_EXPLAINER` (PHP and JS) are duplicated on purpose, and tests enforce that they match. Change both sides.
   - The summary builder expects `asn_org` (snake_case), while workbench rows carry `asnOrg`. `workbench.js` maps between them, and when that mapping was missing the org names silently vanished from the summary.
7. **The GeoLite2 license.** `data/geoip/` must never be web-reachable. CI asserts a 403 on staging and production.
8. **Playwright reuses whatever is already on port 8935** when running locally. A stray `php -S` from another checkout will serve the wrong code. Check with `ss -ltnp | grep 8935`.
9. **Mobile sticky elements.** In the ≤767px block:
   - The pinned first column covers both `#results-table` and `#wb-results-table`.
   - Striped pinned cells need an opaque background: a gradient over `var(--surface)`, not a bare rgba.
   - The sticky header is `top: 0` inside the overflow wrapper. It used to be `top: 56px`, which covered the first rows.
10. **Main is squash-merged.** After a promotion PR, run `scripts/rebase-develop.sh` to realign `develop`. That's why `develop` shows commits "ahead of" `main` that are already live.

## 6. Release runbook for 5.0.0 (only on the owner's explicit go)

**Before:**

- [ ] The owner QAs staging, including a real phone pass at about 390 px.
  - Test plan: `~/.gstack/projects/febrile42-ip2geo/shadows-spamhaus-sync-branch-guard-eng-review-test-plan-20260923-000000.md` (owner machine) plus the mockups. It predates R17, so skip its `PAID_TIER_ENABLED`, legacy paid-report and "IPv6 lookup coming" items: v5 deletes the paid tier and looks up IPv6.
- [ ] The owner finalizes the 5.0.0 entry in `changelog.php` and removes "DRAFT (release date TBD)".
- [ ] Re-dispatch staging if a Spamhaus sync ran since the last deploy, and confirm the footer reads v5.0.0.
- [ ] Decide on the workbench filter-analytics gap (section 8). Either fix it or knowingly ship without it.

**Release:**

1. Rebase `v5` onto the current `origin/main` so it picks up any DROP syncs. Re-run the suites.
2. Open a PR `v5` → `develop` and merge it. Staging deploys from `develop`. Check the footer and staging tests.
3. Open a PR `develop` → `main` and merge it. Production deploys. Then:
   - read `https://ip2geo.org/` back, and check the footer says v5.0.0
   - check the smoke and 403 jobs
   - check that `/api/lookup.php` works
4. Run `scripts/rebase-develop.sh`.
5. Paste an ip2geo.org link into Teams or Slack and check the preview card.
6. Open and merge the `ip2geo-admin` `feat/retire-report-sections` PR. Its JSX was parse-checked only and has **never been viewed in a browser**, so look at it.
7. Tag `v5.0.0`.

**Server and owner steps at release** (outside the repo):

- Remove the `cleanup-reports.php` cron lines, and optionally `cleanup_report_events.php`.
- Remove the Stripe, AbuseIPDB and Resend keys from the live `config.php`.
- After production has v5's `vendor/`, install `scripts/update-geoip.sh` to `~/bin`. It's the version that also refreshes the `.mmdb` files.
- Take a backup, then run `migrations/retire_reports_v5.sql`.
- In Stripe, disable the webhook endpoint and revoke the old keys.

**Rollback:** redeploy the tag `v4-final`. The MySQL GeoIP tables are deliberately kept so v4 still works.

## 7. Open decisions (the owner's call) and later work

- **A past paid customer's report was lost** to a cleanup-script bug in May 2026. Whether to contact or refund them is still open. Details are in the private design doc (R17).
- **Search Console check:** did the April 2026 reskin lose impressions or clicks?
- **The Recent lookups decision** is due around **2026-10-23**, after 30 days of `recent_lookups_use` data (shipped in 4.3.3). Keep the feature or remove it.
- **Retirement notices:**
  - The "Firewall rules moved here" hint is built. It's counted per visitor: 30 days from their first view, in localStorage.
  - The plan's 90-day "old form endpoint" POST response was **not built**. The form POST still works in v5 as the no-JS fallback, so it's probably moot. Confirm with the owner.
- **Later:**
  - drop the legacy MySQL GeoIP tables once v5 has run cleanly. The retired Community Block List's ingestion code (git history, before IPG-23) read `geoip2_asn_current_int`; nothing in v5 does. Decide the `community_*` tables at the same time.
  - a DROP-based block list (replaces the Community Block List, retired in v5.0.0 by IPG-23)
  - the Cloudflare performance spike (parked: "we're doing well with what we have today")

## 8. Known gaps and unverified items

- **The workbench filters send no analytics.** `filter_country`/`filter_category` fire only from the server-rendered table, which JS users no longer see. The approved rule (D9) is a `filter_<dim>` event with the dimension only, never the value. It isn't built yet; see `umami-events.md`.
- **Why free reports stopped after 2026-09-04** was never proven. It looked like "no clicks", but the server error logs couldn't be read. It's moot now that reports are retired.
- **The admin branch** has not been seen in a browser (above).
- **Nothing has been QA'd on a physical phone yet.** Mobile behaviour was verified in Playwright's Pixel 7 emulation against staging.
