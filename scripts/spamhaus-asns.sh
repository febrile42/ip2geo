#!/usr/bin/env bash
# Extract the ASN list from the Spamhaus ASN-DROP feed, one "AS<n>" per line,
# sorted and de-duplicated.
#
# Background: .github/workflows/sync-spamhaus.yml writes each value this script
# emits into asn_classification.php as a PHP string literal ('AS123' =>
# 'scanning'), and that file is auto-promoted to main and deployed to production
# with no human review. The feed is untrusted input, so a value that is not a
# plain positive 32-bit integer ASN must never reach the generated PHP: a record
# like {"asn":"1'.system($_GET[x]).'"} would still pass `php -l`.
#
# Fails closed: on any malformed line, any non-integer / out-of-range .asn, or an
# empty result, it exits non-zero and prints nothing to stdout.
#
# Usage:
#   curl -sf https://www.spamhaus.org/drop/asndrop.json | scripts/spamhaus-asns.sh

set -euo pipefail

# The feed is NDJSON. The first or last record is a {"type":"metadata",...}
# header with no .asn, so records without one are skipped. Every other .asn must
# be an integer in 1..2^32-1; anything else is an error, not a silent skip, so a
# tampered feed stops the sync instead of quietly shrinking the list.
#
# -n with [inputs | ...] runs the whole feed as ONE jq program, so the first
# error aborts it. Filtering record by record instead would not fail closed:
# jq reports an error on one input, carries on, and a later good input (such as
# the trailing metadata line) resets its exit status to 0.
ASNS=$(jq -rn '
  [ inputs
    | select(.asn != null) | .asn
    | if type == "number" and . > 0 and . < 4294967296 and . == floor
      then "AS\(.)"
      else error("unexpected ASN value: \(tojson)")
      end
  ] | .[]
' | sort -u)

if [ -z "$ASNS" ]; then
    echo "Spamhaus ASN-DROP feed yielded no ASNs." >&2
    exit 1
fi

# Second, independent check on the exact text that will be written into PHP.
if echo "$ASNS" | grep -qvxE 'AS[0-9]{1,10}'; then
    echo "Spamhaus ASN-DROP feed yielded an unexpected ASN value." >&2
    exit 1
fi

echo "$ASNS"
