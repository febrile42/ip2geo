#!/usr/bin/env bash
# Clear the APCu page cache for intel.php on the production server.
#
# Background: intel.php caches its rendered HTML in APCu (15-min TTL, keyed by
# UTC date). APCu shared memory is owned by the Apache web process — the CLI PHP
# binary uses a separate pool and cannot reach it. The workaround is to drop a
# self-deleting PHP file into the web root and hit it once via curl.
#
# Usage:
#   ./scripts/clear-intel-cache.sh          # clear prod (ip2geo)
#   ./scripts/clear-intel-cache.sh staging  # clear staging (ip2geo_staging)

set -euo pipefail

TARGET="${1:-prod}"

if [ "$TARGET" = "staging" ]; then
    WEBROOT="$HOME/ip2geo-staging"
    URL="https://staging.ip2geo.org/apcu_clear.php"
else
    WEBROOT="$HOME/ip2geo"
    URL="https://ip2geo.org/apcu_clear.php"
fi

DATE=$(date -u +%Y-%m-%d)
CACHE_KEY="intel_page_7d_${DATE}"

echo "Clearing APCu key: ${CACHE_KEY} on ${TARGET} (${URL})"

ssh lime "echo '<?php apcu_delete(\"${CACHE_KEY}\"); echo \"cleared\"; unlink(__FILE__);' > ${WEBROOT}/apcu_clear.php"
RESULT=$(curl -sf "${URL}")
echo "$RESULT"
