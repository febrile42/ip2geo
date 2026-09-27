# ip2geo.org

Free bulk IP geolocation, ASN and Spamhaus DROP lookup for raw logs. No signup.

Paste a wall of text, log output or a raw list of IPs. ip2geo extracts the IPv4 and IPv6 addresses and returns, for each one:

- country, region and city
- ASN and network name
- a category (scanning, VPN/proxy, cloud, residential), assigned from the network's ASN, not per-IP detection
- a Spamhaus DROP flag (DROP lists IPv4 netblocks only, so IPv6 addresses are never flagged)

One lookup takes up to 10,000 unique IPs and usually finishes in well under a second on the server. You can then filter the results, export them as TSV, CSV, KQL (Sentinel), SPL (Splunk) or iptables/ufw/nginx block rules, and share them as a link that keeps the IPs in the URL fragment. It also works without JavaScript.

Live at [ip2geo.org](https://ip2geo.org) since 2017.

## Privacy

With JavaScript on, your paste stays in the browser: only the extracted IPs are sent to the server, and nothing is logged. Share links keep their IPs in the part of the URL after `#`, which browsers never send to the server. The [privacy page](https://ip2geo.org/privacy.php) covers the details, including the no-JavaScript path.

## Documentation

- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md): stack, local setup, tests, branches, CI/CD and data updates
- [`docs/RETIRED-FEATURES.md`](docs/RETIRED-FEATURES.md): the Threat Reports and Community Block List, retired in v5.0.0
- [`HANDOFF.md`](HANDOFF.md): start here if you are picking up the project

## License

The code is MIT licensed; see [`LICENSE`](LICENSE). The license covers the code only:

- `spamhaus_drop_data.php` and the auto-synced Spamhaus block in `asn_classification.php` are Spamhaus DROP / ASN-DROP data and stay under [Spamhaus's terms](https://www.spamhaus.org/drop/terms/).
- MaxMind GeoLite2 data is not included. To self-host, get your own free MaxMind license key (see [`scripts/fetch-mmdb.sh`](scripts/fetch-mmdb.sh)).
- `tests/fixtures/mmdb/*.mmdb` are MaxMind's test databases, under their own license (see [that folder's README](tests/fixtures/mmdb/README.md)).

## Credits

- Geolocation data: [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). This product includes GeoLite2 data created by MaxMind, available from [maxmind.com](http://www.maxmind.com).
- [Claude Code](https://claude.com/product/claude-code) for helping implement all [my](https://github.com/febrile42/) lingering to-dos and then some.

### Thanks
- ip2geo.org's original HTML/CSS template did a lot of work for a long time: [Hyperspace](https://html5up.net/hyperspace) by [HTML5 UP](https://html5up.net), released under the [CCA 3.0 license](https://html5up.net/license).
