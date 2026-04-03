# ip2geo.org

Three tools in one place.

**Bulk lookup:** paste in a wall of text, log output, or a raw list of IPs — it extracts the addresses, queries the database, and returns country, region, city, ASN, and threat classification for each one. Handles up to 10,000 IPs per request.

**Threat Reports:** paste in a batch of IPs from your server logs and pay once to get back a full threat assessment — a verdict (HIGH / MODERATE / LOW), a breakdown of scanning and proxy infrastructure, AbuseIPDB abuse scores for the worst offenders, ASN CIDR ranges grouped by network, and ready-to-run block scripts for iptables, ufw, and nginx. Useful if you've just stared at a wall of `fail2ban` output and thought "I wonder where all these are coming from, and how do I make them stop."

**Community Block List:** a rolling 7-day feed of CIDR ranges reported by opted-in ip2geo users. Ranges corroborated by three or more independent users (with quality filters to exclude coarse ISP blocks) appear on [`/intel.php`](https://ip2geo.org/intel.php), downloadable as iptables, ufw, nginx, or plain CIDR format.

Live at [ip2geo.org](https://ip2geo.org) since 2017.

---

## Stack

- **PHP** — all server-side logic
- **MySQL / MariaDB** — MaxMind geo data, ASN ranges, reports, and AbuseIPDB cache
- **MaxMind GeoLite2-City + GeoLite2-ASN** — geolocation and ASN data, updated automatically on the 1st of each month
- **Stripe Checkout** — one-time payment for Threat Reports
- **AbuseIPDB** — IP reputation enrichment on paid reports (free tier: 1,000 checks/day)
- **Resend** — email delivery of report links after payment (optional; reports work without it)
- **HTML/CSS** — based on [Hyperspace](https://html5up.net/hyperspace) by HTML5 UP (CCA 3.0)
- **GitHub Actions** — CI/CD pipeline (staging → production) and monthly DB updates
- **APCu** — server-side page cache for `/intel.php` (15-min TTL; downloads bypass)
- **PHPUnit** — 184 tests, 275 assertions covering verdict logic, token lifecycle, webhook handling, ASN classification, AbuseIPDB ranking, cache behaviour, email helpers, community consent flow, and intel page cache logic

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

#### Threat Report tables

Run `scripts/migrate.sql` once before deploying. It's safe to re-run (all statements use `IF NOT EXISTS` guards) and touches nothing that existed before:

```bash
mysql -u youruser -p yourdb < scripts/migrate.sql
```

This creates:

| Table | Contents |
|-------|----------|
| `reports` | Token lifecycle, IP list, report JSON, payment intent, notification email |
| `abuseipdb_cache` | Per-IP AbuseIPDB scores with 7-day TTL |
| `abuseipdb_daily_usage` | Daily API call counter to stay within the free tier limit |

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
| `$stripe_secret_key` | Stripe restricted key (Checkout Sessions → Write only) |
| `$stripe_webhook_secret` | Stripe webhook signing secret (`whsec_...`) |
| `$abuseipdb_api_key` | AbuseIPDB key — leave empty to disable enrichment |
| `$resend_api_key` | Resend API key — leave empty to disable email delivery |
| `$resend_from` | Sender address, e.g. `ip2geo <reports@ip2geo.org>` |

### Stripe

The Threat Report flow requires a Stripe account and a registered webhook endpoint.

**Recommended: use a Stripe Sandbox** for QA and staging. Each sandbox has isolated API keys and delivers webhook events directly to your URL — no Stripe CLI relay needed.

1. Stripe Dashboard → account menu → **Sandboxes** → create one (e.g. "ip2geo QA")
2. Switch into the sandbox → Developers → API keys → copy the `sk_test_...` secret key
3. Developers → Webhooks → Add endpoint:
   - URL: `https://yourdomain.com/webhook.php`
   - Event to subscribe: `checkout.session.completed` (the only one needed)
   - Copy the signing secret (`whsec_...`)
4. Add both to `config.php` on the server

**Minimum API key permissions.** Create a restricted key (Developers → API keys → Create restricted key) with only:

| Permission | Access |
|------------|--------|
| Checkout Sessions | Write |
| Everything else | None |

Stripe automatically grants implied read access on related resources when Checkout Sessions is set to Write — that's expected. A leaked key scoped this way can create payment sessions but cannot read payment data, list customers, or issue refunds.

**Test cards:**

| Card number | Behaviour |
|-------------|-----------|
| `4242 4242 4242 4242` | Successful payment |
| `4000 0000 0000 9995` | Card declined |
| `4000 0025 0000 3155` | 3D Secure required |

Any future expiry date, any 3-digit CVC, any ZIP.

### AbuseIPDB

Sign up at [abuseipdb.com](https://www.abuseipdb.com/account/api) — the free tier provides 1,000 checks/day. Add the key to `config.php`. Leave it empty to disable enrichment without breaking anything else. The daily quota is tracked in `abuseipdb_daily_usage` so lookups degrade gracefully rather than hard-failing when the limit is hit.

### Resend

Sign up at [resend.com](https://resend.com) and verify your sending domain. Add the API key and from address to `config.php`. Leave both empty to skip email delivery — reports are still fully functional, users just need to save their token URL themselves. The `/send-report-link.php` page lets users request a resend at any time while the report is active.

---

## How Threat Reports Work

1. User pastes IPs into the form on the home page. The app classifies each one (scanning, VPN, cloud, residential, unknown) using a combination of known ASN lookups and keyword matching on the org name.
2. If the submission clears the threat threshold, a Stripe Checkout session is created. The IP list is stored in a `pending` token — it expires after 15 minutes if payment doesn't complete.
3. Stripe fires a `checkout.session.completed` webhook. The token is marked `paid`. If the user's browser lands on the success URL first, `report.php` handles the transition directly.
4. On the first visit to `report.php` with a valid paid token, the report is generated: verdict is computed, top-25 IPs are ranked by threat weight, AbuseIPDB scores are fetched for the top entries, and ASN CIDR ranges are pulled from `geoip2_asn_current_int`. The result is stored as JSON and the token is marked `redeemed`.
5. Subsequent visits to the same token URL serve the cached JSON — no recomputation, no additional Stripe or AbuseIPDB calls.
6. If an email address was collected at checkout (or provided later via `/send-report-link.php`), a report link email is sent via Resend. An atomic DB guard prevents duplicate sends if the webhook and the success URL race.
7. Reports expire after 30 days. `scripts/cleanup-reports.php` handles deletion and can be run from cron.

### Verdict logic

| Verdict | Conditions |
|---------|-----------|
| HIGH | ≥250 scanning IPs, or ≥60% scanning with ≥20 absolute, or ≥80% scanning, or any top-5 AbuseIPDB score >80 when MODERATE |
| MODERATE | Everything else; LOW upgrades to MODERATE when cloud traffic is heavy (≥50 IPs or ≥15%) |
| LOW | <10 scanning IPs, or <5% scanning with <25 absolute |

The report includes ready-to-run block scripts for iptables, ufw, and nginx in both IP-list and CIDR-range formats. CIDR ranges are more resilient — they stay valid as individual IPs rotate through an ASN's pool.

### Demo report

A demo report is available at any time at `/?view_token=00000000-0000-0000-0000-000000000000`. It uses pre-seeded data from `scripts/seed-demo-report.php` and demonstrates a HIGH-verdict report with real-looking Tor exit AbuseIPDB scores. Useful for testing the report UI without paying Stripe.

---

## How Community Block List Works

1. After viewing a Threat Report, users are offered the option to share their data. Opting in posts the report's IP list to `community-consent.php` via AJAX.
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

184 tests, 275 assertions. No network calls, no database required — geo lookups and DB interactions are tested against in-memory SQLite mirrors of the production schema.

Test files:

| File | What it covers |
|------|----------------|
| `VerdictAlgorithmTest.php` | `compute_verdict()` and `maybe_upgrade_verdict()` — all threshold combinations |
| `TokenLifecycleTest.php` | Token state machine SQL: pending → paid → redeemed, expiry, submission hash dedup |
| `WebhookHandlerTest.php` | Stripe HMAC verification, event filtering, idempotent DB update, COALESCE email behaviour |
| `EmailHelperTest.php` | `mask_email()`, `build_payment_alert_html()` XSS escaping, atomic email send-slot claim and reset |
| `ReportFunctionsTest.php` | `generate_threat_narrative()`, `compute_abuseipdb_callout()`, `int_range_to_cidr()` |
| `AbuseIPDBRankingTest.php` | `rank_ips()` — threat weight, freq ordering, limit |
| `AsnClassificationTest.php` | `classify_asn()` — known ASN lookups, keyword fallback, edge cases |
| `CacheTest.php` | AbuseIPDB cache hit/miss/expiry, quota tracking, partial cache splits |
| `CommunityConsentTest.php` | Opt-in ingestion, CIDR aggregation, deduplication, decline path, malformed input guards |
| `IntelCacheTest.php` | APCu cache key format, hit/miss/absent paths, ob failure guard, download bypass |

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

- **No Composer in production, except for Stripe and Resend SDKs.** `stripe/stripe-php` handles webhook HMAC verification and Checkout session creation; `resend/resend-php` handles email delivery. Everything else is plain PHP. PHPUnit is dev-only.
- **Speed is a priority.** The app runs on shared hosting with constrained resources. IPs are pre-converted to unsigned 32-bit integers for range queries — this cut lookup time by ~60% over `INET6_ATON()`. A 10,000-IP batch completes in under 2 seconds of database time.
- **`config.php` is the only secret.** DB credentials, Stripe keys, AbuseIPDB key, and Resend key all live there. It's gitignored and the only file that needs to be managed separately on the server.
- **Private IPs are filtered server-side.** RFC 1918 ranges, loopback, and duplicates are stripped before any database queries happen.
- **The token is the access control.** There's no user account system. A paid report is accessible to anyone with the token URL for 30 days, then it's gone. Simple enough to audit, simple enough to explain to a customer.
- **Email is optional end-to-end.** If Resend isn't configured, or if the user doesn't provide an email at checkout, the report is still fully accessible via the token URL. The resend page (`/send-report-link.php`) and the report page both surface the resend link when email is configured. Leaving Resend unconfigured doesn't break anything — it just means users need to save their link themselves.

---

## Credits

- Geolocation data: [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). This product includes GeoLite2 data created by MaxMind, available from [maxmind.com](http://www.maxmind.com).
- HTML/CSS template: [Hyperspace](https://html5up.net/hyperspace) by [HTML5 UP](https://html5up.net), released under the [CCA 3.0 license](https://html5up.net/license).
- [Claude Code](https://claude.com/product/claude-code) for helping implement all [my](https://github.com/febrile42/) lingering to-dos and then some.
