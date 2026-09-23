# ip2geo.org

Two tools in one place.

**Bulk lookup:** paste in a wall of text, log output, or a raw list of IPs — it extracts the addresses, queries the database, and returns country, region, city, ASN, and threat classification for each one. Handles up to 10,000 IPs per request. Threat Reports (the paid one-time report and its free precursor) were retired in v5.0.0 — see "Threat Reports (retired in v5.0.0)" below.

**Community Block List:** a rolling 7-day feed of CIDR ranges reported by opted-in ip2geo users. Ranges corroborated by three or more independent users (with quality filters to exclude coarse ISP blocks) appear on [`/intel.php`](https://ip2geo.org/intel.php), downloadable as iptables, ufw, nginx, or plain CIDR format.

Live at [ip2geo.org](https://ip2geo.org) since 2017.

---

## Stack

- **PHP** — all server-side logic
- **MySQL / MariaDB** — MaxMind geo data and ASN ranges
- **MaxMind GeoLite2-City + GeoLite2-ASN** — geolocation and ASN data, updated automatically on the 1st of each month
- **HTML/CSS** — based on [Hyperspace](https://html5up.net/hyperspace) by HTML5 UP (CCA 3.0)
- **GitHub Actions** — CI/CD pipeline (staging → production) and monthly DB updates
- **APCu** — server-side page cache for `/intel.php` (15-min TTL; downloads bypass)
- **PHPUnit** — covering verdict/Spamhaus DROP logic, ASN classification, community consent flow, and intel page cache logic

No frameworks. No npm. No build step. It's fast on purpose.

---

## Setup

### Prerequisites

- PHP 8.x
- MySQL or MariaDB
- [`geoip2-csv-converter`](https://github.com/maxmind/geoip2-csv-converter) installed on the server
- A MaxMind account with a GeoLite2 license key ([free signup](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data))

### Database

#### Geo tables

Two tables, populated from MaxMind's GeoLite2-City CSV files:

| Table | Contents |
|-------|----------|
| `geoip2_network_current_int` | IPv4 network ranges as integer pairs for fast range lookups |
| `geoip2_location_current` | GeoName ID → country, region, city |
| `geoip2_asn_current_int` | ASN number + org + integer range pairs (populated from GeoLite2-ASN) |

To populate initially: download the GeoLite2-City and GeoLite2-ASN CSV packages from MaxMind, run `geoip2-csv-converter` on the blocks file with `-include-integer-range`, then import via `LOAD DATA LOCAL INFILE`. See `scripts/update-geoip.sh` — it's the same procedure that runs automatically each month.

#### Community Block List tables

Run `scripts/migrate-community.sql` once to add the community tables:

```bash
mysql -u youruser -p yourdb < scripts/migrate-community.sql
```

This creates:

| Table | Contents |
|-------|----------|
| `community_cidr_stats` | Per-CIDR daily report counts and hit totals from opted-in users |
| `community_ip_stats` | Per-IP daily stats for CIDR aggregation |
| `community_ip_first_seen` | Deduplication table — prevents one user from counting the same IP twice per day |
| `community_weekly_stats` | Daily opted-in report counter; used to gate the public feed (minimum 5 reports in a rolling 7-day window) |

Data older than 52 weeks is pruned automatically by the monthly `update-db.yml` workflow.

### Configuration

Copy `config.sample.php` to `config.php` and fill in your credentials:

```bash
cp config.sample.php config.php
```

`config.php` is gitignored and should never be committed. On the server it lives alongside the codebase and survives deploys untouched.

| Variable | Purpose |
|----------|---------|
| `$db_host`, `$db_user`, `$db_pass`, `$db_name` | Database connection |

---

## Threat Reports (retired in v5.0.0)

Through v4, ip2geo also offered a free and a paid ($9) Threat Report: paste a batch of IPs, get back a verdict, AbuseIPDB abuse scores, ASN CIDR ranges, and ready-to-run block scripts, paid via Stripe Checkout and delivered by email via Resend.

That flow is gone as of v5.0.0. `report.php` now returns a static HTTP 410 for every token, including the old demo token, and touches no database. `webhook.php`, `get-report.php`, `send-report-link.php`, `email_helper.php`, and the report-generation half of `report_functions.php` were deleted outright, along with the Stripe and Resend Composer dependencies. `migrations/retire_reports_v5.sql` has the (manual, backup-first) steps to retire the demo token row and, optionally, drop the `reports`, `report_events`, `report_event_rl`, `abuseipdb_cache`, and `abuseipdb_daily_usage` tables.

The Spamhaus DROP reputation axis that used to feed both the lookup CTA and the reports lives on in `report_functions.php` — it's still part of how the free lookup flags residential attackers.

---

## How Community Block List Works

1. ⚠️ **Currently orphaned.** Consent used to be collected on the Threat Report page, which posted the report's IP list to `community-consent.php` via AJAX after opt-in. That page is gone as of v5.0.0 (see "Threat Reports" above), so `community-consent.php` has no caller left in the app. The community tables and `/intel.php` feed below are untouched (Open Question 4 — whether to keep, fold into DROP intel, or retire the Community Block List — is still open), but new opt-ins can't happen until that question is settled and a new consent entry point is built.
2. The consent endpoint ingests IPs, computes CIDR ranges via `geoip2_asn_current_int`, and writes daily rows to `community_cidr_stats` and `community_ip_stats`. Each IP is deduplicated per user per day via `community_ip_first_seen` — one user reporting the same IP 100 times counts as one report.
3. `/intel.php` queries the rolling 7-day window. A range appears on the public list only if it passes all three quality filters:
   - **3+ independent reports** — corroborated by at least three distinct opted-in users
   - **Prefix /16 or more specific** — excludes coarse ASN-level blocks covering millions of IPs
   - **Hit density ≥ 0.1%** — at least 1 observed hit per 1,000 addresses in the range (filters incidental overlap)
4. The page is APCu-cached for 15 minutes. Downloads (iptables, ufw, nginx, plain CIDR) bypass the cache and always query the database directly.
5. The public feed requires a minimum of 5 opted-in reports in the past 7 days before any data is shown. Below that threshold, the page displays a "not enough data yet" message rather than a sparse or misleading list.

Residential IPs are never collected — the consent flow only ingests IPs classified as scanning, proxy, VPN, or cloud infrastructure. Data is retained for 52 weeks.

---

## Development

### Workflow

Two-branch model:

- **`develop`** — working branch. Push here freely. Automatically deploys to staging and runs tests.
- **`main`** — production branch. Only updated by merging from `develop` via PR. Automatically deploys to production.

```bash
# Day to day
git checkout develop
# ... make changes ...
git add -p && git commit -m "..."
git push origin develop
# Pipeline: staging deploy → smoke + functional + performance tests

# When ready to go live
# Open a PR from develop → main, merge, pipeline deploys to production
```

### Tests

```bash
composer install
./vendor/bin/phpunit --testdox
```

No network calls, no database required — geo lookups and DB interactions are tested against in-memory SQLite mirrors of the production schema.

Test files:

| File | What it covers |
|------|----------------|
| `SpamhausDropTest.php` | Spamhaus DROP lookup, the generator, and `apply_reputation_override()` — the CTA override on residential attackers |
| `AsnClassificationTest.php` | `classify_asn()` — known ASN lookups, keyword fallback, edge cases |
| `CommunityConsentTest.php` | Opt-in ingestion, CIDR aggregation, deduplication, decline path, malformed input guards |
| `IntelCacheTest.php` | APCu cache key format, hit/miss/absent paths, ob failure guard, download bypass |
| `ReportRetiredTest.php` | `report.php` returns HTTP 410 for any token (or none) and never touches the database |

### CI/CD Pipeline

Tests run on GitHub's infrastructure, not on the server. Smoke and functional tests hit the origin directly with `Host:` headers, bypassing Cloudflare so results reflect actual PHP and DB performance rather than whatever the CDN cached.

The performance test compares staging against production and fails if staging regresses by more than 25% against an absolute 6-second ceiling. This has caught real problems.

See `.github/workflows/` for the full pipeline definition.

### Database Updates

`scripts/update-geoip.sh` handles the monthly GeoLite2 refresh:

1. Downloads the latest GeoLite2-City and GeoLite2-ASN CSVs from MaxMind
2. Converts network blocks to integer ranges via `geoip2-csv-converter`
3. Imports into shadow tables
4. Verifies row counts (≥90% of current) and spot-checks a known IP (8.8.8.8 → US)
5. Atomically swaps shadow tables into production via `RENAME TABLE`
6. Rolls back automatically if anything looks wrong

Runs on the 1st of each month via `update-db.yml`. Also triggers a Spamhaus ASN-DROP diff to flag ASNs newly added to the blocklist — these are reviewed and fed into `asn_classification.php` as needed.

---

## Design Notes

A few intentional choices worth noting:

- **No Composer packages in production.** `maxmind-db/reader` reads the `.mmdb` geo/ASN files. Everything else is plain PHP. PHPUnit is dev-only.
- **Speed is a priority.** The app runs on shared hosting with constrained resources. IPs are pre-converted to unsigned 32-bit integers for range queries — this cut lookup time by ~60% over `INET6_ATON()`. A 10,000-IP batch completes in under 2 seconds of database time.
- **`config.php` is the only secret.** DB credentials live there. It's gitignored and the only file that needs to be managed separately on the server.
- **Private IPs are filtered server-side.** RFC 1918 ranges, loopback, and duplicates are stripped before any database queries happen.

---

## Credits

- Geolocation data: [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). This product includes GeoLite2 data created by MaxMind, available from [maxmind.com](http://www.maxmind.com).
- [Claude Code](https://claude.com/product/claude-code) for helping implement all [my](https://github.com/febrile42/) lingering to-dos and then some.

### Thanks
- ip2geo.org's original HTML/CSS template did a lot of work for a long time: [Hyperspace](https://html5up.net/hyperspace) by [HTML5 UP](https://html5up.net), released under the [CCA 3.0 license](https://html5up.net/license).
