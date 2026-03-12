# MaxMind GeoLite2 Database Update Plan

## What You're Building

A monthly automated process that:
1. Downloads the latest GeoLite2-City CSV from MaxMind
2. Imports it into shadow tables on the Linode
3. Verifies the new data before touching anything live
4. Atomically swaps the new tables into production
5. Keeps the previous data as a one-cycle rollback net
6. Notifies you automatically (via GitHub) if anything goes wrong

The site continues serving from the old data throughout — the only interruption is a MariaDB `RENAME TABLE` that takes milliseconds.

---

## Validating Your Approach: CSV vs Binary (.mmdb)

**CSV is correct.** The `.mmdb` binary format would require MaxMind's PHP library, which means Composer. That's a dependency that violates this project's philosophy and would add meaningful complexity. The CSV + SQL approach you're already using is:

- Zero new PHP dependencies
- Already working and benchmarked
- `geoip2-csv-converter` already installed at `/usr/bin/geoip2-csv-converter`
- Proven to produce the integer-range tables the query needs

Stay on CSV.

---

## Current State (confirmed)

| Table | Rows | Purpose |
|---|---|---|
| `geoip2_network_20250401_int` | 3,323,333 | IP range → geoname_id lookup |
| `geoip2_location_20250401` | 77,521 | geoname_id → city/country data |
| `locations` | unknown | legacy; used only for country list |

**The core problem for automation:** table names are hardcoded with a date in `index.php`. Every update would require a code change. The fix is a one-time refactor to use stable names — after that, the automation only touches the database and never needs to know about PHP.

---

## One-Time Prerequisite Changes

### 1. Stable table names in `index.php`

Change the two hardcoded table references:

| Old (date-stamped) | New (stable) |
|---|---|
| `geoip2_network_20250401_int` | `geoip2_network_current_int` |
| `geoip2_location_20250401` | `geoip2_location_current` |

Also update the country list query to eliminate the legacy `locations` dependency:

```sql
-- Old (queries legacy table)
SELECT DISTINCT(`country_iso_code`) FROM `locations`

-- New (queries the live data directly)
SELECT DISTINCT(`country_iso_code`) FROM `geoip2_location_current`
WHERE `country_iso_code` IS NOT NULL
```

This removes `locations` as a table that needs to be maintained going forward.

### 2. Create initial stable-name tables from existing data

On the Linode (one time):

```sql
RENAME TABLE
  geoip2_network_20250401_int TO geoip2_network_current_int,
  geoip2_location_20250401 TO geoip2_location_current;
```

Deploy the PHP change first, then run this rename. The PHP and DB stay in sync.

### 3. ~~Verify `LOAD DATA LOCAL INFILE`~~ ✅ Confirmed

`local_infile` is `ON` on the Linode. No server config change needed. The update script will use `LOAD DATA LOCAL INFILE` (client-side, no `FILE` privilege required) and the `ip2geo` user's existing `CREATE/DROP/ALTER/INSERT` grants cover everything else.

### 4. Drop legacy tables (one-time cleanup)

Several tables in the `ip2geo` database are no longer in use. Drop them after the stable-name rename (step 2 above) is confirmed working:

```sql
-- Legacy tables with no current code references
DROP TABLE IF EXISTS geoip2_location;
DROP TABLE IF EXISTS geoip2_network;
DROP TABLE IF EXISTS geoip2_network_20250401;   -- non-integer version, superseded by _int
DROP TABLE IF EXISTS locations;                  -- replaced by querying geoip2_location_current
```

> **Before dropping:** confirm none of these appear in any active PHP file. A quick grep: `grep -r "geoip2_location\b\|geoip2_network\b\|geoip2_network_20250401\b\|locations" /var/www/ip2geo/*.php` should return zero results after the `index.php` update is deployed.

### 5. Add new GitHub Secrets

| Secret | Value |
|---|---|
| `MAXMIND_ACCOUNT_ID` | Your MaxMind Account ID |
| `MAXMIND_LICENSE_KEY` | Your MaxMind License Key |

---

## The Update Script

A shell script lives on the Linode at `~/bin/update-geoip.sh`. It is called by the GitHub Actions workflow — it does all the heavy work.

```
Step 1: Download
  - wget MaxMind permalink with Basic Auth (Account ID + License Key)
  - → /tmp/geoip-update/GeoLite2-City-CSV.zip

Step 2: Unzip
  - Extract to /tmp/geoip-update/
  - → GeoLite2-City-Blocks-IPv4.csv
  - → GeoLite2-City-Locations-en.csv

Step 3: Convert blocks CSV
  - geoip2-csv-converter -block-file ... -output-file ... -include-integer-range
  - → /tmp/geoip-update/network_int.csv

Step 4: Create shadow tables
  - CREATE TABLE geoip2_network_incoming_int (...)
  - CREATE TABLE geoip2_location_incoming (...)

Step 5: Import
  - LOAD DATA LOCAL INFILE network_int.csv INTO TABLE geoip2_network_incoming_int
  - LOAD DATA LOCAL INFILE GeoLite2-City-Locations-en.csv INTO TABLE geoip2_location_incoming

Step 6: Verify (pre-swap)
  - Row count check: incoming_int must have >= 90% of current rows (3,323,333 baseline)
  - Row count check: incoming location must have >= 90% of current rows (77,521 baseline)
  - Spot check: query geoip2_network_incoming_int for 8.8.8.8 → expect a US geoname_id
  - Spot check: join incoming tables, confirm 8.8.8.8 → "United States"
  → If any check fails: DROP shadow tables, exit non-zero (GitHub Actions reports failure)

Step 7: Atomic swap
  RENAME TABLE
    geoip2_network_current_int TO geoip2_network_backup_int,
    geoip2_network_incoming_int TO geoip2_network_current_int,
    geoip2_location_current TO geoip2_location_backup,
    geoip2_location_incoming TO geoip2_location_current;
  -- All four renames happen in a single statement — atomic, zero downtime

Step 8: Update data version
  - UPDATE db_meta SET value = CURDATE() WHERE key_name = 'data_last_updated';
  - Write db_version.php to both webroots (gitignored; included at top of index.php with zero DB overhead):
      DATE_LABEL=$(date +"%B %Y")
      echo "<?php \$db_data_date = '$DATE_LABEL'; ?>" | tee /var/www/ip2geo/db_version.php /var/www/ip2geo-staging/db_version.php
  - This surfaces in the ip2geo.org footer as "Data: [Month Year]" on all page loads, not just POST

Step 9: Post-swap verification
  - Re-run the 8.8.8.8 spot check against the now-live geoip2_network_current_int
  → If this fails: RENAME back (swap _backup → _current), exit non-zero

Step 9: Drop previous backup tables
  - DROP TABLE IF EXISTS geoip2_network_backup_int;
  - DROP TABLE IF EXISTS geoip2_location_backup;
  - These are the tables from the *previous* successful run, now two cycles old.
  - After this step, the only tables in ip2geo are:
      geoip2_network_current_int   ← live, just updated
      geoip2_location_current      ← live, just updated
  - Clean slate every cycle. No accumulation of old dated tables.

Step 10: Cleanup
  - rm -rf /tmp/geoip-update/
```

**On failure at any step:** the script exits non-zero. GitHub Actions marks the run as failed, sends you an email, and the site continues serving from `geoip2_network_current_int` — which is unchanged because the swap either never happened or was reversed in step 8.

---

## GitHub Actions Scheduled Workflow

A second workflow file: `.github/workflows/update-db.yml`

```yaml
name: Monthly GeoIP Database Update

on:
  schedule:
    - cron: '0 3 1 * *'   # 3am UTC on the 1st of every month
  workflow_dispatch:        # allow manual trigger from GitHub UI

jobs:
  update-geoip:
    name: Update GeoLite2-City Database
    runs-on: ubuntu-latest

    steps:
      - name: Run update script on Linode
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.DEPLOY_HOST }}
          username: ${{ secrets.DEPLOY_USER }}
          key: ${{ secrets.DEPLOY_SSH_KEY }}
          port: ${{ secrets.DEPLOY_PORT }}
          command_timeout: 30m   # import can take several minutes
          script: |
            ~/bin/update-geoip.sh \
              "${{ secrets.MAXMIND_ACCOUNT_ID }}" \
              "${{ secrets.MAXMIND_LICENSE_KEY }}"

      - name: Smoke test — production still returns HTTP 200
        run: |
          sleep 5
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Host: ip2geo.org" \
            "http://${{ secrets.DEPLOY_HOST }}")
          if [ "$STATUS" != "200" ]; then
            echo "Post-update smoke test failed: HTTP $STATUS"
            exit 1
          fi
          echo "Post-update smoke test passed"

      - name: Functional test — known IP still resolves correctly
        run: |
          RESPONSE=$(curl -s -X POST \
            -H "Host: ip2geo.org" \
            "http://${{ secrets.DEPLOY_HOST }}" \
            --data-urlencode "ip_list=8.8.8.8" \
            -d "submit=1")
          if echo "$RESPONSE" | grep -qiE "United States|>US<"; then
            echo "Functional test passed"
          else
            echo "Functional test failed: 8.8.8.8 did not resolve to US after update"
            exit 1
          fi
```

**`workflow_dispatch`** means you can trigger it manually from the GitHub Actions tab at any time — useful for the first run or for ad-hoc updates.

---

## Failure Behavior

| Failure point | What happens |
|---|---|
| MaxMind download fails | Script exits, old data untouched, GH notifies you |
| Import fails partway | Shadow tables dropped, old data untouched, GH notifies you |
| Verification fails (row count or spot check) | Shadow tables dropped, old data untouched, GH notifies you |
| Post-swap verification fails | Tables renamed back to previous state, GH notifies you |
| Smoke/functional test in GH Actions fails | You're notified; data may be live but site is functional (the script's own post-swap check already ran) |

In every failure scenario, the site keeps working on the previous data. The only exception would be a catastrophic Linode failure mid-rename, which MariaDB handles as a crash-safe transaction anyway.

---

## Manual Rollback

If the worst somehow happens and you need to roll back:

```bash
ssh lime
mysql -u ip2geo -p ip2geo
```

```sql
-- Swap back (backup tables exist for one full cycle after each successful update)
RENAME TABLE
  geoip2_network_current_int TO geoip2_network_current_int_bad,
  geoip2_network_backup_int  TO geoip2_network_current_int,
  geoip2_location_current    TO geoip2_location_current_bad,
  geoip2_location_backup     TO geoip2_location_current;
```

---

## Can This Be Truly Automated Once Per Month?

**Yes, with one caveat.**

The caveat: MaxMind occasionally restructures their CSV schema between major releases. If column names or order change, `LOAD DATA LOCAL INFILE` will import garbage silently — this is caught by the row count check (if columns shift, the import produces wrong row counts) and more reliably by the spot check (8.8.8.8 will return NULL instead of United States). So the verification layer is the bulletproof part.

In practice, MaxMind has kept the GeoLite2-City CSV schema stable for years. The risk is low but real, and the checks handle it.

**Practical recommendation:** the first run should be manual (trigger via `workflow_dispatch`) while you're available. After confirming it works end-to-end, let it run unattended monthly.

---

## New Secrets Needed

| Secret | Notes |
|---|---|
| `MAXMIND_ACCOUNT_ID` | Found at maxmind.com → Account → My Account |
| `MAXMIND_LICENSE_KEY` | The key you just created |

Total GitHub Secrets after this: 8 (the existing 6 + 2 new).

---

## Open Items Before Executing

1. **Verify `local_infile`** — run `SHOW VARIABLES LIKE 'local_infile'` on the Linode. If OFF, needs a one-time root-level server config change.
2. **Write the `update-geoip.sh` script** — the actual shell script with all the SQL inline. This is mechanical once the plan is approved.
3. **Code change to `index.php`** — replace date-stamped table names with stable names + update the country list query.
4. **Initial rename** — `RENAME TABLE` the existing 2025 tables to `_current` names after the PHP change deploys.
