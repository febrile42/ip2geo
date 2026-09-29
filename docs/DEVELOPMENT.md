# Developing ip2geo

How ip2geo is built, set up, tested and deployed. For what the site does, see the [README](../README.md). **Picking this up cold? Read [`HANDOFF.md`](../HANDOFF.md) first.**

---

## Stack

- **PHP 8.4**: all server-side logic. No framework.
- **MaxMind GeoLite2-City + GeoLite2-ASN `.mmdb` files**: the lookup reads them with `maxmind-db/reader` (`includes/lookup.php`). Production also has the `php-maxminddb` C extension, which the reader uses automatically. It makes a 10k-IP lookup take ~0.2–0.5 s instead of ~3.5 s.
- **MySQL / MariaDB**: the retired Community Block List tables (kept, nothing reads them), plus the legacy GeoIP integer-range tables (`geoip2_*_current_int`). Nothing in v5 reads the GeoIP tables any more. They are dropped once v5 has run cleanly for a while.
- **Vanilla JS, no build step**: the v5 workbench (`assets/js/*.js`) extracts IPs in the browser, POSTs only the IPs to `/api/lookup.php`, and renders, filters and exports on the client. Without JS, `index.php` falls back to a server-rendered results table.
- **Cloudflare** in front of the origin. Rocket Loader is on for the zone, so every `<script>` tag carries `data-cfasync="false"` (enforced by `tests/RocketLoaderOptOutTest.php`), and every asset URL carries `?v=<APP_VERSION>` so a release is never paired with day-old cached JS.
- **APCu**: the lookup rate limit (`/api/lookup.php` and the no-JS `POST /`).
- **GitHub Actions**: CI/CD (tests → staging → production), weekly GeoLite2 refresh, and Spamhaus DROP / ASN-DROP syncs.
- **Tests**: PHPUnit, plus Jest and Playwright (dev-only; nothing Node-based is deployed).

---

## Setup

### Prerequisites

- PHP 8.4 with APCu. `php-maxminddb` is strongly recommended for speed.
- MySQL or MariaDB, with the server time zone set to UTC (see the comment at the top of `config.sample.php`)
- Composer
- A MaxMind account with a GeoLite2 license key ([free signup](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data))
- For the legacy MySQL GeoIP tables only: [`geoip2-csv-converter`](https://github.com/maxmind/geoip2-csv-converter)

### Lookup data (`.mmdb`)

```bash
MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... scripts/fetch-mmdb.sh "$PWD"
```

This writes `data/geoip/GeoLite2-{City,ASN}.mmdb`. The script:

- verifies SHA256
- spot-checks 8.8.8.8 → US / AS15169
- swaps the files in atomically
- does nothing if both files are less than 7 days old

Credentials come from the environment and are never passed as arguments. `data/geoip/` is gitignored, and `data/.htaccess` denies web access, because the GeoLite2 license forbids redistribution. CI checks that the directory returns 403 on staging and production.

For local development and tests, copy the tiny MaxMind test databases instead:

```bash
mkdir -p data/geoip
cp tests/fixtures/mmdb/GeoIP2-City-Test.mmdb data/geoip/GeoLite2-City.mmdb
cp tests/fixtures/mmdb/GeoLite2-ASN-Test.mmdb data/geoip/GeoLite2-ASN.mmdb
```

### Database

v5 needs no database. The tables below belong to the retired Community Block List and are kept for now; the now-removed `scripts/migrate-community.sql` created them (see git history):

| Table | Contents |
|-------|----------|
| `community_cidr_stats` | Per-CIDR daily report counts and hit totals from opted-in users |
| `community_ip_stats` | Per-IP daily stats for CIDR aggregation |
| `community_ip_first_seen` | Deduplication table: one user can count the same IP only once per day |
| `community_weekly_stats` | Daily opted-in report counter. The public feed needs at least 5 reports in a rolling 7-day window |

The legacy GeoIP tables (`geoip2_network_current_int`, `geoip2_location_current`, `geoip2_asn_current_int`) are built and refreshed by `scripts/update-geoip.sh`.

### Configuration

```bash
cp config.sample.php config.php
```

`config.php` holds the DB credentials and, optionally, a `GEOIP_MMDB_DIR` override (default `<app>/data/geoip`). It is gitignored. On the server it lives beside the code and survives deploys.

---

## Workflow

### Branches

- **`develop`**: pushes deploy to staging and run the staging tests.
- **`main`**: production. It is updated only by merging `develop` in via PR, and every push deploys to production. Promotions are squash-merged, so run `scripts/rebase-develop.sh` afterwards to realign `develop`.
- **`v5`** (until the 5.0.0 release): the whole v5 rewrite. It is kept off `develop` on purpose, because the Spamhaus syncs (the weekly DROP sync and the monthly ASN-DROP sync) auto-promote `develop` → `main` whenever the delta is only their data files. Deploy it to staging with `gh workflow run deploy.yml --ref v5`, and re-run that after every Monday DROP sync. See `HANDOFF.md` for the release steps.

Commit messages on `v5` are plain declarative sentences saying what the user now sees ("Tapping a DROP label opens a popover…"). Earlier history uses `chore:`/`feat:` prefixes.

### Tests

```bash
composer install && vendor/bin/phpunit          # PHP: no network, no MySQL (SQLite mirrors + test .mmdb fixtures)
npm ci && npx jest                               # JS units (jsdom)
cp config.sample.php config.php                  # then copy the test .mmdb files (see "Lookup data")
npx playwright test                              # browser specs; starts php -S on 127.0.0.1:8935
```

`IP2GEO_E2E_FORCE_UMAMI=1` makes the privacy spec load the analytics script so it can assert what gets sent. CI sets it. If port 8935 is taken by a stray `php -S`, Playwright reuses that server locally, so kill it first if it belongs to another checkout.

| Suite | Covers |
|-------|--------|
| `ExtractIpsTest.php`, `tests/js/extract-ips.test.js` | IP extraction, locked to shared golden fixtures in `tests/fixtures/extract` (PHP and JS must agree) |
| `LookupTest.php`, `LookupAutoloadTest.php` | `lookup_ips()` against test `.mmdb` files; Composer autoload in a fresh process |
| `ApiLookupTest.php` | `/api/lookup.php` contract: 413 caps, 429 rate limit, 503 on missing data |
| `IndexResultsTest.php`, `SummaryTest.php`, `DropExplainerTest.php` | No-JS results page, summary line, and the DROP explainer text staying identical in PHP and JS |
| `SampleLogTest.php` | "Try a sample log" never labels a real person's IP |
| `SpamhausDropTest.php`, `AsnClassificationTest.php` | DROP lookup and generator; ASN classification |
| `IntelRetiredTest.php` | `/intel.php` 410 (Community Block List retired) |
| `ReportRetiredTest.php`, `IpValidationTest.php` | `report.php` 410; IP validation |
| `RocketLoaderOptOutTest.php` | Every script tag carries `data-cfasync="false"` |
| `tests/js/*.test.js` | Filters, exports, share links, summary, workbench rendering, DROP popover, Recent lookups |
| `tests/e2e/privacy.spec.js` | No paste text in any request; IPs only in the `/api/lookup.php` body; no `#v=` content in analytics |
| `tests/e2e/a11y.spec.js` | axe scan of the results page and workbench (fails on serious or critical issues) |
| `tests/e2e/drop-tap.spec.js` | On phones: tap a DROP label for the explanation; the IP column stays pinned while scrolling sideways |

### CI/CD Pipeline

`.github/workflows/deploy.yml` works like this:

1. **Every push, PR and dispatch:** PHP lint plus the full test job.
2. **Staging deploy:** a push to `develop`, or a dispatch on `v5`. It runs:
   - `git reset --hard` to the branch
   - `composer install --no-dev`
   - `scripts/fetch-mmdb.sh`
3. **Staging tests:** these hit the origin directly with `Host:` headers, bypassing Cloudflare:
   - smoke test
   - `data/geoip` returns 403
   - known-IP functional check
   - a 10k-IP performance test, which fails over 6 s or on a >25% regression against production
4. **Production:** a push to `main` runs the same deploy steps plus smoke and 403 checks.

Other workflows:

| Workflow | Schedule | What it does |
|---|---|---|
| `update-db.yml` | Weekly (Mon) | Runs `~/bin/update-geoip.sh` on the server |
| `sync-spamhaus-drop.yml` | Weekly | Syncs Spamhaus DROP and auto-promotes if the delta is pure data |
| `sync-spamhaus.yml` | Monthly | Regenerates the ASN-DROP auto-sync block in `asn_classification.php` on `develop`, and auto-promotes if the delta is pure Spamhaus |

### Database Updates

`scripts/update-geoip.sh` does the monthly GeoLite2 refresh for both the `.mmdb` files and the legacy MySQL tables. It runs on the server from `~/bin`, triggered by `update-db.yml`. For the MySQL tables it:

1. imports the CSVs into shadow tables
2. verifies row counts (at least 90% of current) and spot-checks 8.8.8.8
3. swaps the shadow tables in with `RENAME TABLE`
4. rolls back if anything looks wrong

For the `.mmdb` files it:

1. verifies the checksums and spot-checks 8.8.8.8
2. `mv`s the files into production's and staging's `GEOIP_MMDB_DIR`

---

## Design Notes

- **Speed is the product.** The `.mmdb` reader with the C extension, client-side extraction (a 2 MB worst-case paste parses in ~55 ms), and client-side filtering keep a 10k-IP triage interactive.
- **The paste stays in the browser when JS is on.** Only the extracted IPs are sent, and nothing is logged. Share links keep their IPs in the `#v=` fragment, which is stripped before analytics runs. `privacy.php` describes both the JS and no-JS paths exactly. Keep it true.
- **Composer in production is `maxmind-db/reader` only.** PHPUnit, Jest and Playwright are dev-only.
- **`config.php` is the only server-managed file** besides `data/geoip/`.
- **Private and reserved IPs are filtered before lookup** (RFC 1918, loopback, link-local, ULA and the like).
