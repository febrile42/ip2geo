#!/bin/bash
# Monthly GeoLite2-City + GeoLite2-ASN database update
# Usage: update-geoip.sh ACCOUNT_ID LICENSE_KEY
#
# Runs on the deployment server. Install to ~/bin/update-geoip.sh and chmod +x.
# Triggered monthly by .github/workflows/update-db.yml via SSH.
set -euo pipefail

ACCOUNT_ID="${1:?MaxMind Account ID required}"
LICENSE_KEY="${2:?MaxMind License Key required}"

PROD_PATH="/var/www/ip2geo"
STAGING_PATH="/var/www/ip2geo-staging"
WORK_DIR="$HOME/geoip-update"

CITY_ZIP_URL="https://download.maxmind.com/geoip/databases/GeoLite2-City-CSV/download?suffix=zip"
CITY_SHA_URL="https://download.maxmind.com/geoip/databases/GeoLite2-City-CSV/download?suffix=zip.sha256"
ASN_ZIP_URL="https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip"
ASN_SHA_URL="https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip.sha256"

# .mmdb editions (R4) — same account/license key as the CSVs above, just a
# different edition + suffix on the same download API.
CITY_MMDB_TGZ_URL="https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
CITY_MMDB_SHA_URL="https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz.sha256"
ASN_MMDB_TGZ_URL="https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz"
ASN_MMDB_SHA_URL="https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz.sha256"

# Read DB credentials from config.php (single source of truth)
DB_HOST=$(php -r "require '$PROD_PATH/config.php'; echo \$db_host;")
DB_USER=$(php -r "require '$PROD_PATH/config.php'; echo \$db_user;")
DB_PASS=$(php -r "require '$PROD_PATH/config.php'; echo \$db_pass;")
DB_NAME=$(php -r "require '$PROD_PATH/config.php'; echo \$db_name;")

# Read the .mmdb target directory from each environment's own config.php.
# config.php (copied from config.sample.php) defines GEOIP_MMDB_DIR itself,
# falling back to /var/www/geoip if the operator never overrode it there;
# includes/lookup.php carries the same fallback for anything that requires
# it without config.php. If config.php can't be read at all, fall back here too.
PROD_MMDB_DIR=$(php -r "require '$PROD_PATH/config.php'; echo defined('GEOIP_MMDB_DIR') ? GEOIP_MMDB_DIR : '/var/www/geoip';" 2>/dev/null || echo '/var/www/geoip')
STAGING_MMDB_DIR=$(php -r "require '$STAGING_PATH/config.php'; echo defined('GEOIP_MMDB_DIR') ? GEOIP_MMDB_DIR : '/var/www/geoip';" 2>/dev/null || echo '/var/www/geoip')

# Write credentials to a temp file so they never appear in the process list
MYCNF=$(mktemp)
chmod 600 "$MYCNF"
printf '[client]\nhost=%s\nuser=%s\npassword=%s\ndatabase=%s\n' \
  "$DB_HOST" "$DB_USER" "$DB_PASS" "$DB_NAME" > "$MYCNF"
MYSQL="mysql --defaults-extra-file=$MYCNF"
cleanup() { rm -f "$MYCNF"; rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# Download a file and verify its SHA256. Retries once on failure, then exits.
# Usage: download_verified LABEL ZIP_URL SHA256_URL OUTPUT_FILE
download_verified() {
  local label="$1" zip_url="$2" sha_url="$3" out="$4"
  local attempt
  for attempt in 1 2; do
    wget -q --user="$ACCOUNT_ID" --password="$LICENSE_KEY" "$zip_url" -O "$out"
    local expected actual
    expected=$(wget -q --user="$ACCOUNT_ID" --password="$LICENSE_KEY" -O - "$sha_url" | awk '{print $1}')
    actual=$(sha256sum "$out" | awk '{print $1}')
    if [ "$expected" = "$actual" ]; then
      echo "  SHA256 verified: $actual"
      return 0
    fi
    echo "  SHA256 mismatch (attempt $attempt/2): expected=$expected actual=$actual"
    rm -f "$out"
  done
  echo "FAIL: $label SHA256 verification failed after 2 attempts. Aborting."
  exit 1
}

rm -rf "$WORK_DIR" && mkdir -p "$WORK_DIR"

echo "[1/19] Downloading GeoLite2-City CSV..."
download_verified "City" "$CITY_ZIP_URL" "$CITY_SHA_URL" "$WORK_DIR/GeoLite2-City-CSV.zip"

echo "[2/19] Downloading GeoLite2-ASN CSV..."
download_verified "ASN" "$ASN_ZIP_URL" "$ASN_SHA_URL" "$WORK_DIR/GeoLite2-ASN-CSV.zip"

echo "[3/19] Extracting archives..."
unzip -q "$WORK_DIR/GeoLite2-City-CSV.zip" -d "$WORK_DIR/city"
unzip -q "$WORK_DIR/GeoLite2-ASN-CSV.zip"  -d "$WORK_DIR/asn"
CITY_DIR=$(find "$WORK_DIR/city" -maxdepth 1 -mindepth 1 -type d | head -1)
ASN_DIR=$(find "$WORK_DIR/asn"  -maxdepth 1 -mindepth 1 -type d | head -1)

echo "[4/19] Converting City blocks to integer-range format..."
geoip2-csv-converter \
  -block-file "$CITY_DIR/GeoLite2-City-Blocks-IPv4.csv" \
  -output-file "$CITY_DIR/network_int.csv" \
  -include-integer-range
# Converter output columns:
#   network_start_integer, network_last_integer, geoname_id,
#   registered_country_geoname_id, represented_country_geoname_id,
#   is_anonymous_proxy, is_satellite_provider, postal_code,
#   latitude, longitude, accuracy_radius, is_anycast

echo "[5/19] Converting ASN blocks to integer-range format..."
geoip2-csv-converter \
  -block-file "$ASN_DIR/GeoLite2-ASN-Blocks-IPv4.csv" \
  -output-file "$ASN_DIR/asn_int.csv" \
  -include-integer-range
# Converter output columns:
#   network_start_integer, network_last_integer,
#   autonomous_system_number, autonomous_system_organization

echo "[6/19] Creating shadow tables..."
$MYSQL <<SQL
DROP TABLE IF EXISTS geoip2_network_incoming_int;
DROP TABLE IF EXISTS geoip2_location_incoming;
DROP TABLE IF EXISTS geoip2_asn_incoming_int;
CREATE TABLE geoip2_network_incoming_int LIKE geoip2_network_current_int;
CREATE TABLE geoip2_location_incoming    LIKE geoip2_location_current;
-- ASN table: create from scratch if this is the first run
-- INT UNSIGNED (not BIGINT) matches the city table and halves the index key size.
-- Covering index includes ASN number + org so lookups never touch the row heap.
CREATE TABLE IF NOT EXISTS geoip2_asn_current_int (
  network_start_integer INT UNSIGNED NOT NULL,
  network_end_integer   INT UNSIGNED NOT NULL,
  autonomous_system_number INT UNSIGNED,
  autonomous_system_org    VARCHAR(255),
  KEY idx_asn_lookup (network_start_integer, autonomous_system_number, autonomous_system_org)
) ENGINE=InnoDB;
CREATE TABLE geoip2_asn_incoming_int LIKE geoip2_asn_current_int;
SQL

echo "[7/19] Importing City network blocks (~3.3M rows)..."
$MYSQL --local-infile=1 -e "
LOAD DATA LOCAL INFILE '$CITY_DIR/network_int.csv'
INTO TABLE geoip2_network_incoming_int
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
(network_start_integer, @net_last, geoname_id, registered_country_geoname_id,
 represented_country_geoname_id, is_anonymous_proxy, is_satellite_provider,
 postal_code, latitude, longitude, accuracy_radius, is_anycast)
SET network_end_integer = @net_last;"

echo "[8/19] Importing City location data..."
$MYSQL --local-infile=1 -e "
LOAD DATA LOCAL INFILE '$CITY_DIR/GeoLite2-City-Locations-en.csv'
INTO TABLE geoip2_location_incoming
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;"

echo "[9/19] Importing ASN data (~400K rows)..."
$MYSQL --local-infile=1 -e "
LOAD DATA LOCAL INFILE '$ASN_DIR/asn_int.csv'
INTO TABLE geoip2_asn_incoming_int
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
(network_start_integer, @net_last, autonomous_system_number, autonomous_system_org)
SET network_end_integer = @net_last;"

echo "[10/19] Verifying City data..."
CURRENT_NET=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_network_current_int;")
INCOMING_NET=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_network_incoming_int;")
CURRENT_LOC=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_location_current;")
INCOMING_LOC=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_location_incoming;")
echo "  Network: current=$CURRENT_NET incoming=$INCOMING_NET"
echo "  Location: current=$CURRENT_LOC incoming=$INCOMING_LOC"

MIN_NET=$(awk "BEGIN { printf \"%d\", $CURRENT_NET * 0.9 }")
MIN_LOC=$(awk "BEGIN { printf \"%d\", $CURRENT_LOC * 0.9 }")
if [ "$INCOMING_NET" -lt "$MIN_NET" ] || [ "$INCOMING_LOC" -lt "$MIN_LOC" ]; then
  echo "FAIL: City row count below 90% of current — aborting before swap"
  $MYSQL -e "
    DROP TABLE IF EXISTS geoip2_network_incoming_int;
    DROP TABLE IF EXISTS geoip2_location_incoming;
    DROP TABLE IF EXISTS geoip2_asn_incoming_int;"
  exit 1
fi

# Spot check: 8.8.8.8 = 134744072 -> US
SPOT=$($MYSQL -sN -e "
SELECT l.country_iso_code
FROM geoip2_network_incoming_int n
LEFT JOIN geoip2_location_incoming l
  ON l.geoname_id = n.geoname_id AND l.locale_code = 'en'
WHERE 134744072 >= n.network_start_integer
  AND 134744072 <= n.network_end_integer
ORDER BY n.network_start_integer DESC LIMIT 1;")
if [ "$SPOT" != "US" ]; then
  echo "FAIL: City spot check (8.8.8.8) returned '$SPOT' (expected US)"
  $MYSQL -e "
    DROP TABLE IF EXISTS geoip2_network_incoming_int;
    DROP TABLE IF EXISTS geoip2_location_incoming;
    DROP TABLE IF EXISTS geoip2_asn_incoming_int;"
  exit 1
fi
echo "  City spot check passed: 8.8.8.8 -> $SPOT"

echo "[11/19] Verifying ASN data..."
CURRENT_ASN=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_asn_current_int;")
INCOMING_ASN=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_asn_incoming_int;")
echo "  ASN: current=$CURRENT_ASN incoming=$INCOMING_ASN"

# On first run current is 0; skip the 90% floor check and only spot-check
if [ "$CURRENT_ASN" -gt 0 ]; then
  MIN_ASN=$(awk "BEGIN { printf \"%d\", $CURRENT_ASN * 0.9 }")
  if [ "$INCOMING_ASN" -lt "$MIN_ASN" ]; then
    echo "FAIL: ASN row count below 90% of current — aborting before swap"
    $MYSQL -e "
      DROP TABLE IF EXISTS geoip2_network_incoming_int;
      DROP TABLE IF EXISTS geoip2_location_incoming;
      DROP TABLE IF EXISTS geoip2_asn_incoming_int;"
    exit 1
  fi
fi

# Spot check: 8.8.8.8 = 134744072 -> AS15169 (Google)
ASN_SPOT=$($MYSQL -sN -e "
SELECT autonomous_system_number
FROM geoip2_asn_incoming_int
WHERE 134744072 >= network_start_integer
  AND 134744072 <= network_end_integer
ORDER BY network_start_integer DESC LIMIT 1;")
if [ "$ASN_SPOT" != "15169" ]; then
  echo "FAIL: ASN spot check (8.8.8.8) returned AS$ASN_SPOT (expected AS15169 Google)"
  $MYSQL -e "
    DROP TABLE IF EXISTS geoip2_network_incoming_int;
    DROP TABLE IF EXISTS geoip2_location_incoming;
    DROP TABLE IF EXISTS geoip2_asn_incoming_int;"
  exit 1
fi
echo "  ASN spot check passed: 8.8.8.8 -> AS$ASN_SPOT"

echo "[12/19] Atomic swap (City + ASN)..."
$MYSQL <<SQL
RENAME TABLE
  geoip2_network_current_int TO geoip2_network_backup_int,
  geoip2_network_incoming_int TO geoip2_network_current_int,
  geoip2_location_current TO geoip2_location_backup,
  geoip2_location_incoming TO geoip2_location_current,
  geoip2_asn_current_int TO geoip2_asn_backup_int,
  geoip2_asn_incoming_int TO geoip2_asn_current_int;
SQL

echo "[13/19] Updating db_meta..."
DATE_LABEL=$(date +"%B %Y")
$MYSQL -e "UPDATE db_meta SET value = CURDATE() WHERE key_name = 'data_last_updated';"
printf '<?php $db_data_date = '"'"'%s'"'"'; ?>\n' "$DATE_LABEL" \
  | tee "$PROD_PATH/db_version.php" "$STAGING_PATH/db_version.php" > /dev/null

echo "[14/19] Post-swap verification..."
POST_SPOT=$($MYSQL -sN -e "
SELECT l.country_iso_code
FROM geoip2_network_current_int n
LEFT JOIN geoip2_location_current l
  ON l.geoname_id = n.geoname_id AND l.locale_code = 'en'
WHERE 134744072 >= n.network_start_integer
  AND 134744072 <= n.network_end_integer
ORDER BY n.network_start_integer DESC LIMIT 1;")
if [ "$POST_SPOT" != "US" ]; then
  echo "FAIL: Post-swap City spot check failed. Rolling back..."
  $MYSQL <<SQL
RENAME TABLE
  geoip2_network_current_int TO geoip2_network_incoming_int,
  geoip2_network_backup_int TO geoip2_network_current_int,
  geoip2_location_current TO geoip2_location_incoming,
  geoip2_location_backup TO geoip2_location_current,
  geoip2_asn_current_int TO geoip2_asn_incoming_int,
  geoip2_asn_backup_int TO geoip2_asn_current_int;
SQL
  exit 1
fi
echo "  City post-swap: 8.8.8.8 -> $POST_SPOT"

POST_ASN=$($MYSQL -sN -e "
SELECT autonomous_system_number
FROM geoip2_asn_current_int
WHERE 134744072 >= network_start_integer
  AND 134744072 <= network_end_integer
ORDER BY network_start_integer DESC LIMIT 1;")
if [ "$POST_ASN" != "15169" ]; then
  echo "FAIL: Post-swap ASN spot check failed. Rolling back..."
  $MYSQL <<SQL
RENAME TABLE
  geoip2_network_current_int TO geoip2_network_incoming_int,
  geoip2_network_backup_int TO geoip2_network_current_int,
  geoip2_location_current TO geoip2_location_incoming,
  geoip2_location_backup TO geoip2_location_current,
  geoip2_asn_current_int TO geoip2_asn_incoming_int,
  geoip2_asn_backup_int TO geoip2_asn_current_int;
SQL
  exit 1
fi
echo "  ASN post-swap: 8.8.8.8 -> AS$POST_ASN"

echo "[15/19] Dropping backup tables..."
$MYSQL -e "
  DROP TABLE IF EXISTS geoip2_network_backup_int;
  DROP TABLE IF EXISTS geoip2_location_backup;
  DROP TABLE IF EXISTS geoip2_asn_backup_int;"

echo "Done. GeoLite2 City + ASN updated to $DATE_LABEL (MySQL tables)."

# ── .mmdb download (R4) ────────────────────────────────────────────────────
# MySQL is done and swapped above; this section is independent of it (the
# MySQL tables stay in place until the HTML page is switched to lookup_ips(),
# per the design doc). A failure below leaves the previous .mmdb files in
# place untouched — mmdb_atomic_swap only replaces them once a new file has
# already been downloaded, verified and extracted successfully.

echo "[16/19] Downloading GeoLite2-City .mmdb..."
download_verified "City .mmdb" "$CITY_MMDB_TGZ_URL" "$CITY_MMDB_SHA_URL" "$WORK_DIR/GeoLite2-City-mmdb.tar.gz"

echo "[17/19] Downloading GeoLite2-ASN .mmdb..."
download_verified "ASN .mmdb" "$ASN_MMDB_TGZ_URL" "$ASN_MMDB_SHA_URL" "$WORK_DIR/GeoLite2-ASN-mmdb.tar.gz"

echo "[18/19] Extracting .mmdb archives..."
mkdir -p "$WORK_DIR/city-mmdb" "$WORK_DIR/asn-mmdb"
tar -xzf "$WORK_DIR/GeoLite2-City-mmdb.tar.gz" -C "$WORK_DIR/city-mmdb"
tar -xzf "$WORK_DIR/GeoLite2-ASN-mmdb.tar.gz"  -C "$WORK_DIR/asn-mmdb"
CITY_MMDB_SRC=$(find "$WORK_DIR/city-mmdb" -name 'GeoLite2-City.mmdb' | head -1)
ASN_MMDB_SRC=$(find "$WORK_DIR/asn-mmdb"  -name 'GeoLite2-ASN.mmdb'  | head -1)
if [ -z "$CITY_MMDB_SRC" ] || [ -z "$ASN_MMDB_SRC" ]; then
  echo "FAIL: extracted archive did not contain the expected .mmdb file. Old files kept in place."
  exit 1
fi
# Sanity check both files parse and answer the same 8.8.8.8 / AS15169 spot
# check used for the MySQL tables above, using the reader this app ships
# (composer.json: maxmind-db/reader). A bad extract must not reach prod.
php -r "
require '$PROD_PATH/vendor/autoload.php';
foreach (['$CITY_MMDB_SRC' => 'country', '$ASN_MMDB_SRC' => 'asn'] as \$path => \$kind) {
    \$r = new MaxMind\Db\Reader(\$path);
    \$rec = \$r->get('8.8.8.8');
    \$r->close();
    if (\$kind === 'country' && (\$rec['country']['iso_code'] ?? null) !== 'US') {
        fwrite(STDERR, \"FAIL: City .mmdb spot check (8.8.8.8) did not return US\n\");
        exit(1);
    }
    if (\$kind === 'asn' && (\$rec['autonomous_system_number'] ?? null) !== 15169) {
        fwrite(STDERR, \"FAIL: ASN .mmdb spot check (8.8.8.8) did not return AS15169\n\");
        exit(1);
    }
}
echo \"  .mmdb spot checks passed: 8.8.8.8 -> US / AS15169\n\";
"

# Atomic swap: write to a temp name in the SAME directory as the target (so
# the rename is on one filesystem, and never durably visible half-written),
# then mv -f over the live file. Applied to both prod and staging mmdb dirs.
mmdb_atomic_swap() {
  local src="$1" dest_dir="$2" dest_name="$3"
  mkdir -p "$dest_dir"
  local tmp="$dest_dir/.${dest_name}.tmp.$$"
  cp "$src" "$tmp"
  mv -f "$tmp" "$dest_dir/$dest_name"
}

echo "[19/19] Atomic swap of .mmdb files (prod + staging)..."
mmdb_atomic_swap "$CITY_MMDB_SRC" "$PROD_MMDB_DIR"    "GeoLite2-City.mmdb"
mmdb_atomic_swap "$ASN_MMDB_SRC"  "$PROD_MMDB_DIR"    "GeoLite2-ASN.mmdb"
mmdb_atomic_swap "$CITY_MMDB_SRC" "$STAGING_MMDB_DIR" "GeoLite2-City.mmdb"
mmdb_atomic_swap "$ASN_MMDB_SRC"  "$STAGING_MMDB_DIR" "GeoLite2-ASN.mmdb"
echo "  Swapped into $PROD_MMDB_DIR and $STAGING_MMDB_DIR"

echo "Done. GeoLite2 City + ASN updated to $DATE_LABEL (MySQL tables + .mmdb files)."
