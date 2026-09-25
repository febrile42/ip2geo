<?php
// Copy this file to config.php and fill in your credentials
//
// SERVER REQUIREMENT: MariaDB must be configured to use UTC.
// Add to /etc/mysql/mariadb.conf.d/50-server.cnf under [mariadbd]:
//   default-time-zone = '+00:00'
// Then restart: sudo systemctl restart mariadb
// Verify: mysql -e "SELECT @@global.time_zone;"  → must return +00:00
// PHP runs in UTC; a timezone mismatch breaks the DATETIME comparisons used
// by the community-block-list and intel-cache windows.
$db_host = 'localhost';
$db_user = 'your_db_user';
$db_pass = 'your_db_password';
$db_name = 'your_db_name';

// GeoIP .mmdb directory (R4) — where scripts/update-geoip.sh atomically drops
// GeoLite2-City.mmdb and GeoLite2-ASN.mmdb each month, and where
// includes/lookup.php's lookup_ips() reads them from by default. Defaults to
// <app>/data/geoip (the same fallback includes/lookup.php uses), which is
// gitignored and denied to the web by data/.htaccess; scripts/fetch-mmdb.sh
// fills it on every deploy. Override only if the files live elsewhere.
// Must be readable by the webserver user. Missing or corrupt files
// make lookup_ips() throw GeoDbUnavailableException, which api/lookup.php
// turns into a 503.
if (!defined('GEOIP_MMDB_DIR')) {
    define('GEOIP_MMDB_DIR', __DIR__ . '/data/geoip');
}
