# ip2geo.org

Bulk IPv4 geolocation lookup tool. Paste in a wall of text, log output, or a raw list of IPs — it extracts the addresses, queries the database, and returns country, region, and city for each one. Handles up to 10,000 IPs per request.

Useful if you've just stared at a wall of `fail2ban` output and thought "I wonder where all these are coming from."

Live at [ip2geo.org](https://ip2geo.org) since 2017.

---

## Stack

- **PHP** — server-side lookup logic
- **MySQL** (or MariaDB) — hosts the MaxMind GeoLite2-City data
- **MaxMind GeoLite2-City** — the geolocation data, updated automatically on the 1st of each month
- **HTML/CSS** — based on [Hyperspace](https://html5up.net/hyperspace) by HTML5 UP (CCA 3.0)
- **GitHub Actions** — CI/CD pipeline (lint → staging → production) and monthly DB updates

No frameworks. No package managers. No build step. It's fast on purpose.

---

## Setup

### Prerequisites

- PHP 8.x
- MySQL or MariaDB
- [`geoip2-csv-converter`](https://github.com/maxmind/geoip2-csv-converter) installed on the server
- A MaxMind account with a GeoLite2 license key ([free signup](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data))

### Database

Two tables, populated from MaxMind's GeoLite2-City CSV files:

| Table | Contents |
|-------|----------|
| `geoip2_network_current_int` | IPv4 network ranges stored as integer pairs for fast range lookups |
| `geoip2_location_current` | GeoName ID → country, region, city |

To populate initially: download the GeoLite2-City CSV package from MaxMind, run `geoip2-csv-converter` on the blocks file with `-include-integer-range`, then import both the converted network CSV and the locations CSV via `LOAD DATA LOCAL INFILE`. See `scripts/update-geoip.sh` for the exact procedure — the same script runs automatically each month, so it's worth understanding.

### Configuration

Copy `config.sample.php` to `config.php` and fill in your database credentials:

```bash
cp config.sample.php config.php
```

`config.php` is gitignored and should never be committed. On the server it lives alongside the codebase and survives deploys untouched.

---

## Development

### Workflow

This project uses a two-branch model:

- **`develop`** — working branch. Push here freely. Automatically deploys to staging and runs tests.
- **`main`** — production branch. Only updated by merging from `develop`. Automatically deploys to production.

The rule: work on `develop`, verify on staging, merge to `main` when ready.

```bash
# Day to day
git checkout develop
# ... make changes ...
git add -p && git commit -m "..."
git push origin develop
# Pipeline runs: lint → staging deploy → smoke/functional/performance tests

# When ready to go live
git checkout main && git merge develop && git push origin main
# Pipeline runs: lint → production deploy → smoke test
```

### CI/CD Pipeline

Tests run on GitHub's infrastructure, not on the server. All test requests bypass Cloudflare by hitting the origin directly with `Host:` headers — smoke tests reflect actual PHP health, and performance numbers reflect actual database query time rather than whatever the CDN cached.

The performance test compares staging against production and fails if it regresses by more than 25%. This has caught real problems.

See `.github/workflows/` for the full pipeline definition.

### Database Updates

`scripts/update-geoip.sh` handles the monthly GeoLite2 refresh:

1. Downloads the latest GeoLite2-City CSV from MaxMind
2. Converts network blocks to integer ranges via `geoip2-csv-converter`
3. Imports into shadow tables (`geoip2_network_incoming_int`, `geoip2_location_incoming`)
4. Verifies row counts (≥90% of current) and spot-checks a known IP (8.8.8.8 → US)
5. Atomically swaps shadow tables into production via `RENAME TABLE`
6. Updates the data freshness date displayed in the footer
7. Rolls back automatically if anything looks wrong

This runs on the 1st of each month via `update-db.yml`. It can also be triggered manually from the Actions tab if you don't feel like waiting.

---

## Design Notes

A few intentional choices worth noting:

- **No Composer, no npm.** Dependencies add surface area. The stack is PHP + SQL and that's sufficient.
- **Speed is a priority.** The app runs on shared hosting with constrained resources. IPs are pre-converted to unsigned 32-bit integers for range queries — this cut lookup time by ~60% over `INET6_ATON()`. A 10,000-IP batch completes in under 2 seconds of database time.
- **`config.php` is the only secret.** DB credentials live there, it's gitignored, and it's the only file that needs to be managed separately on the server. Keep it that way.
- **Private IPs are filtered server-side.** RFC 1918 ranges (10.x, 192.168.x, 172.16–31.x), loopback (127.x, ::1), and duplicates are stripped before any database queries happen.

---

## Credits

- Geolocation data: [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). This product includes GeoLite2 data created by MaxMind, available from [maxmind.com](http://www.maxmind.com).
- HTML/CSS template: [Hyperspace](https://html5up.net/hyperspace) by [HTML5 UP](https://html5up.net), released under the [CCA 3.0 license](https://html5up.net/license).
- [Claude Code](https://claude.com/product/claude-code) for helping implement all [my](https://github.com/febrile42/) lingering to-dos and then some.
