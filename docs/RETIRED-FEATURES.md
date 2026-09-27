# Retired features

Threat Reports and the Community Block List were part of ip2geo through v4 and were retired in v5.0.0. This page records what was removed, what was kept and why.

---

## Threat Reports (retired in v5.0.0)

Through v4, ip2geo also offered a free and a paid ($9) Threat Report. You pasted a batch of IPs and got back a verdict, AbuseIPDB abuse scores, ASN CIDR ranges and ready-to-run block scripts. Payment went through Stripe Checkout and the report was emailed via Resend.

That flow is gone as of v5.0.0:

- **`report.php`** now returns a static HTTP 410 for every token, including the old demo token, and touches no database.
- **Deleted outright:**
  - `webhook.php`, `get-report.php`, `send-report-link.php` and `email_helper.php`
  - the report-generation half of `report_functions.php`
  - the Stripe and Resend Composer dependencies
- **`migrations/retire_reports_v5.sql`** has the manual, backup-first steps to:
  - retire the demo token row
  - optionally drop the `reports`, `report_events`, `report_event_rl`, `abuseipdb_cache` and `abuseipdb_daily_usage` tables

The Spamhaus DROP check lives on in `report_functions.php` and in the lookup's DROP flag. It is a local list (`spamhaus_drop_data.php`, synced weekly), not an API call, so it has no quota.

---

## Community Block List (retired in v5.0.0)

The list was fed by opt-ins on the Threat Report page, so it had no source left once reports were retired, and production's list was already empty. The owner retired it in v5.0.0 (IPG-7 option 2A, IPG-23):

- `/intel.php` returns a static 410 page for every request, including the old `?format=` download URLs. It never touches the database.
- `community-consent.php` (the opt-in endpoint) is deleted, so it 404s. The deploy workflow checks that it stays unreachable.
- The `community_*` tables are **kept** for now. The old page, the consent ingestion code and the CIDR thresholds are in git history (before IPG-23).
- A DROP-based block list is on the post-release roadmap.

When the legacy tables are cleaned up: the old ingestion code computed CIDR ranges from `geoip2_asn_current_int`, so a revived community list built the old way would need that table.
