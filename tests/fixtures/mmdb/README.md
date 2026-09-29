# Test fixtures: MaxMind test .mmdb databases

`GeoIP2-City-Test.mmdb` and `GeoLite2-ASN-Test.mmdb` are MaxMind's own
synthetic test databases, used here so `tests/LookupTest.php` and
`tests/ApiLookupTest.php` can exercise `includes/lookup.php`'s
`lookup_ips()` offline, without the real (license-restricted) GeoLite2
data.

- Source: https://github.com/maxmind/MaxMind-DB, `test-data/` directory
- Fetched: 2026-09-23, from the `main` branch
- License: the MaxMind-DB repository is Apache License 2.0 **or** MIT, at
  the user's option (see `LICENSE-APACHE` / `LICENSE-MIT` there). The task
  brief for this lane assumed CC-BY-SA for these files; that was checked
  against the repo's actual `README.md` and corrected here — Apache-2.0/MIT
  applies, not CC-BY-SA.
- These are small, fixed, non-authoritative test databases (a handful of
  synthetic records — e.g. `81.2.69.142` → London, GB; `1.0.0.1` → AS15169
  Google Inc.). They are not the real, redistribution-restricted GeoLite2
  City/ASN databases that `scripts/update-geoip.sh` downloads to
  `GEOIP_MMDB_DIR` in production.
