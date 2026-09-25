#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
NAME="silk-specter-v3-v${VERSION}"
OUT="${1:-$(dirname "$ROOT")}"
mkdir -p "$OUT"
rm -f "$OUT/$NAME.zip" "$OUT/$NAME-SHA256SUMS.txt"
(
  cd "$(dirname "$ROOT")"
  zip -qr "$OUT/$NAME.zip" "$(basename "$ROOT")" \
    -x '*/__pycache__/*' '*/.git/*' '*/dist/*'
)
sha256sum "$OUT/$NAME.zip" > "$OUT/$NAME-SHA256SUMS.txt"
echo "$OUT/$NAME.zip"
echo "$OUT/$NAME-SHA256SUMS.txt"
