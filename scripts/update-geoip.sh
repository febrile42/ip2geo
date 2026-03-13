#!/bin/bash
# Monthly GeoLite2-City database update
# Usage: update-geoip.sh ACCOUNT_ID LICENSE_KEY
#
# Runs on the Linode as shadows. Install to ~/bin/update-geoip.sh and chmod +x.
# Triggered monthly by .github/workflows/update-db.yml via SSH.
set -euo pipefail

ACCOUNT_ID="${1:?MaxMind Account ID required}"
LICENSE_KEY="${2:?MaxMind License Key required}"

PROD_PATH="/var/www/ip2geo"
STAGING_PATH="/var/www/ip2geo-staging"
WORK_DIR="/home/shadows/geoip-update"

# Read DB credentials from config.php (single source of truth)
DB_HOST=$(php -r "require '$PROD_PATH/config.php'; echo \$db_host;")
DB_USER=$(php -r "require '$PROD_PATH/config.php'; echo \$db_user;")
DB_PASS=$(php -r "require '$PROD_PATH/config.php'; echo \$db_pass;")
DB_NAME=$(php -r "require '$PROD_PATH/config.php'; echo \$db_name;")

# Write credentials to a temp file so they never appear in the process list
MYCNF=$(mktemp)
chmod 600 "$MYCNF"
printf '[client]\nhost=%s\nuser=%s\npassword=%s\ndatabase=%s\n' \
  "$DB_HOST" "$DB_USER" "$DB_PASS" "$DB_NAME" > "$MYCNF"
MYSQL="mysql --defaults-extra-file=$MYCNF"
cleanup() { rm -f "$MYCNF"; rm -rf "$WORK_DIR"; }
trap cleanup EXIT

echo "[1/10] Downloading GeoLite2-City CSV..."
rm -rf "$WORK_DIR" && mkdir -p "$WORK_DIR"
wget -q --user="$ACCOUNT_ID" --password="$LICENSE_KEY" \
  "https://download.maxmind.com/geoip/databases/GeoLite2-City-CSV/download?suffix=zip" \
  -O "$WORK_DIR/GeoLite2-City-CSV.zip"

echo "[2/10] Extracting..."
unzip -q "$WORK_DIR/GeoLite2-City-CSV.zip" -d "$WORK_DIR"
EXTRACT_DIR=$(find "$WORK_DIR" -maxdepth 1 -mindepth 1 -type d | head -1)

echo "[3/10] Converting blocks to integer-range format..."
geoip2-csv-converter \
  -block-file "$EXTRACT_DIR/GeoLite2-City-Blocks-IPv4.csv" \
  -output-file "$EXTRACT_DIR/network_int.csv" \
  -include-integer-range
# Note: converter output columns are: network_start_integer, network_last_integer,
# geoname_id, registered_country_geoname_id, represented_country_geoname_id,
# is_anonymous_proxy, is_satellite_provider, postal_code, latitude, longitude,
# accuracy_radius, is_anycast  (no CIDR column; network_last = network_end)

echo "[4/10] Creating shadow tables..."
$MYSQL <<SQL
DROP TABLE IF EXISTS geoip2_network_incoming_int;
DROP TABLE IF EXISTS geoip2_location_incoming;
CREATE TABLE geoip2_network_incoming_int LIKE geoip2_network_current_int;
CREATE TABLE geoip2_location_incoming LIKE geoip2_location_current;
SQL

echo "[5/10] Importing network blocks (~3.3M rows, takes a few minutes)..."
$MYSQL --local-infile=1 -e "
LOAD DATA LOCAL INFILE '$EXTRACT_DIR/network_int.csv'
INTO TABLE geoip2_network_incoming_int
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
(network_start_integer, @net_last, geoname_id, registered_country_geoname_id, represented_country_geoname_id,
 is_anonymous_proxy, is_satellite_provider, postal_code, latitude, longitude,
 accuracy_radius, is_anycast)
SET network_end_integer = @net_last;"

echo "[6/10] Importing location data..."
$MYSQL --local-infile=1 -e "
LOAD DATA LOCAL INFILE '$EXTRACT_DIR/GeoLite2-City-Locations-en.csv'
INTO TABLE geoip2_location_incoming
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;"

echo "[7/10] Verifying new data..."
CURRENT_NET=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_network_current_int;")
INCOMING_NET=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_network_incoming_int;")
CURRENT_LOC=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_location_current;")
INCOMING_LOC=$($MYSQL -sN -e "SELECT COUNT(*) FROM geoip2_location_incoming;")
echo "Network: current=$CURRENT_NET incoming=$INCOMING_NET"
echo "Location: current=$CURRENT_LOC incoming=$INCOMING_LOC"

MIN_NET=$(awk "BEGIN { printf \"%d\", $CURRENT_NET * 0.9 }")
MIN_LOC=$(awk "BEGIN { printf \"%d\", $CURRENT_LOC * 0.9 }")
if [ "$INCOMING_NET" -lt "$MIN_NET" ] || [ "$INCOMING_LOC" -lt "$MIN_LOC" ]; then
  echo "FAIL: row count below 90% threshold"
  $MYSQL -e "DROP TABLE IF EXISTS geoip2_network_incoming_int; DROP TABLE IF EXISTS geoip2_location_incoming;"
  exit 1
fi

# Spot check: 8.8.8.8 = integer 134744072 -> should resolve to US
SPOT=$($MYSQL -sN -e "
SELECT l.country_iso_code
FROM geoip2_network_incoming_int n
LEFT JOIN geoip2_location_incoming l
  ON l.geoname_id = n.geoname_id AND l.locale_code = 'en'
WHERE 134744072 >= n.network_start_integer
  AND 134744072 <= n.network_end_integer
ORDER BY n.network_start_integer DESC LIMIT 1;")

if [ "$SPOT" != "US" ]; then
  echo "FAIL: 8.8.8.8 spot check returned '$SPOT' (expected US)"
  $MYSQL -e "DROP TABLE IF EXISTS geoip2_network_incoming_int; DROP TABLE IF EXISTS geoip2_location_incoming;"
  exit 1
fi
echo "Spot check passed: 8.8.8.8 -> $SPOT"

echo "[8/10] Atomic swap..."
$MYSQL <<SQL
RENAME TABLE
  geoip2_network_current_int TO geoip2_network_backup_int,
  geoip2_network_incoming_int TO geoip2_network_current_int,
  geoip2_location_current TO geoip2_location_backup,
  geoip2_location_incoming TO geoip2_location_current;
SQL

DATE_LABEL=$(date +"%B %Y")
$MYSQL -e "UPDATE db_meta SET value = CURDATE() WHERE key_name = 'data_last_updated';"
printf '<?php $db_data_date = '"'"'%s'"'"'; ?>\n' "$DATE_LABEL" \
  | tee "$PROD_PATH/db_version.php" "$STAGING_PATH/db_version.php" > /dev/null

echo "[9/10] Post-swap verification..."
POST_SPOT=$($MYSQL -sN -e "
SELECT l.country_iso_code
FROM geoip2_network_current_int n
LEFT JOIN geoip2_location_current l
  ON l.geoname_id = n.geoname_id AND l.locale_code = 'en'
WHERE 134744072 >= n.network_start_integer
  AND 134744072 <= n.network_end_integer
ORDER BY n.network_start_integer DESC LIMIT 1;")

if [ "$POST_SPOT" != "US" ]; then
  echo "FAIL: post-swap spot check failed. Rolling back..."
  $MYSQL <<SQL
RENAME TABLE
  geoip2_network_current_int TO geoip2_network_incoming_int,
  geoip2_network_backup_int TO geoip2_network_current_int,
  geoip2_location_current TO geoip2_location_incoming,
  geoip2_location_backup TO geoip2_location_current;
SQL
  exit 1
fi
echo "Post-swap passed: 8.8.8.8 -> $POST_SPOT"

echo "[10/10] Dropping old backup tables..."
$MYSQL -e "DROP TABLE IF EXISTS geoip2_network_backup_int; DROP TABLE IF EXISTS geoip2_location_backup;"

echo "Done! GeoLite2 data updated to $DATE_LABEL."
