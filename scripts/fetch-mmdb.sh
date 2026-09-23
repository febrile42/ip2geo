#!/bin/bash
# Fetch the MaxMind GeoLite2 City + ASN .mmdb files that includes/lookup.php reads.
# Usage (credentials come from the environment, never argv):
#   MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... scripts/fetch-mmdb.sh <app-dir>
# Writes <app-dir>/data/geoip/GeoLite2-{City,ASN}.mmdb. data/.htaccess denies web
# access: GeoLite2's license forbids redistributing the files.
# Skips the download when both files exist and are newer than 35 days, so it is
# cheap to run on every deploy. The monthly update-geoip.sh also refreshes them.
#
#   files fresh? ──yes──▶ exit 0
#        │no
#        ▼
#   download .tar.gz + .sha256 (netrc, basic auth) ─▶ verify SHA256
#        ▼
#   extract ─▶ spot check 8.8.8.8 = US / AS15169 ─▶ atomic mv into place
set -euo pipefail

APP_DIR="${1:?app dir required}"
DEST="$APP_DIR/data/geoip"
: "${MAXMIND_ACCOUNT_ID:?MAXMIND_ACCOUNT_ID not set}"
: "${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY not set}"

mkdir -p "$DEST"
if [ -n "$(find "$DEST" -maxdepth 1 -name 'GeoLite2-City.mmdb' -mtime -35)" ] &&
   [ -n "$(find "$DEST" -maxdepth 1 -name 'GeoLite2-ASN.mmdb' -mtime -35)" ]; then
  echo "mmdb files are fresh (<35 days); nothing to do."
  exit 0
fi

WORK=$(mktemp -d)
NETRC="$WORK/netrc"
trap 'rm -rf "$WORK"' EXIT
( umask 077; printf 'machine download.maxmind.com login %s password %s\n' \
    "$MAXMIND_ACCOUNT_ID" "$MAXMIND_LICENSE_KEY" > "$NETRC" )

for EDITION in GeoLite2-City GeoLite2-ASN; do
  URL="https://download.maxmind.com/geoip/databases/$EDITION/download?suffix=tar.gz"
  curl -fsSL --netrc-file "$NETRC" -o "$WORK/$EDITION.tar.gz" "$URL"
  EXPECTED=$(curl -fsSL --netrc-file "$NETRC" "$URL.sha256" | awk '{print $1}')
  ACTUAL=$(sha256sum "$WORK/$EDITION.tar.gz" | awk '{print $1}')
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "FAIL: $EDITION SHA256 mismatch (expected $EXPECTED, got $ACTUAL)"; exit 1
  fi
  mkdir -p "$WORK/$EDITION"
  tar -xzf "$WORK/$EDITION.tar.gz" -C "$WORK/$EDITION"
  SRC=$(find "$WORK/$EDITION" -name "$EDITION.mmdb" | head -1)
  [ -n "$SRC" ] || { echo "FAIL: $EDITION.mmdb not found in archive"; exit 1; }
  cp "$SRC" "$WORK/$EDITION.mmdb"
done

php -r '
require $argv[1] . "/vendor/autoload.php";
$c = new MaxMind\Db\Reader($argv[2]); $a = new MaxMind\Db\Reader($argv[3]);
$cc = $c->get("8.8.8.8")["country"]["iso_code"] ?? null;
$asn = $a->get("8.8.8.8")["autonomous_system_number"] ?? null;
if ($cc !== "US" || $asn !== 15169) { fwrite(STDERR, "FAIL: spot check got $cc / AS$asn\n"); exit(1); }
echo "Spot check passed: 8.8.8.8 -> US / AS15169\n";
' "$APP_DIR" "$WORK/GeoLite2-City.mmdb" "$WORK/GeoLite2-ASN.mmdb"

for EDITION in GeoLite2-City GeoLite2-ASN; do
  cp "$WORK/$EDITION.mmdb" "$DEST/.$EDITION.mmdb.tmp.$$"
  mv -f "$DEST/.$EDITION.mmdb.tmp.$$" "$DEST/$EDITION.mmdb"
done
echo "Installed GeoLite2 City + ASN .mmdb into $DEST"
