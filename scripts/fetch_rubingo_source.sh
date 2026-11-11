#!/usr/bin/env bash
set -euo pipefail
BASE="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED='39f780813e558f390a9404964e1d9ec80748e66f'
if [ -s "$BASE/server/rubingo/rubingo.go" ] && [ -s "$BASE/server/RUBINGO_LICENSE.txt" ]; then
  echo 'Pinned Rubingo source already present.'
  exit 0
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
git clone --filter=blob:none https://github.com/farshadnobody/Rubingo.git "$TMP/Rubingo"
git -C "$TMP/Rubingo" checkout "$EXPECTED"
ACTUAL=$(git -C "$TMP/Rubingo" rev-parse HEAD)
[ "$ACTUAL" = "$EXPECTED" ] || { echo 'Unexpected upstream revision' >&2; exit 1; }
install -m 0644 "$TMP/Rubingo/rubingo/rubingo.go" "$BASE/server/rubingo/rubingo.go"
install -m 0644 "$TMP/Rubingo/LICENSE" "$BASE/server/RUBINGO_LICENSE.txt"
echo "Fetched MIT Rubingo source at $EXPECTED; no APK copied."
