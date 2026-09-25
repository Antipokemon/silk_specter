#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${1:-/tmp/silk-specter-v3-easy}"
INDEX="${2:-asteron_easy}"
HEC_FILE="$DATA_DIR/hec/events.jsonl"
MANIFEST="$DATA_DIR/manifest.json"

if [[ ! -f "$HEC_FILE" ]]; then
  echo "Missing canonical ingest stream: $HEC_FILE" >&2
  exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Missing manifest: $MANIFEST" >&2
  exit 1
fi

EXPECTED="$(python3 - "$MANIFEST" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['events'])
PY
)"
LINES="$(wc -l < "$HEC_FILE" | tr -d ' ')"

if [[ "$LINES" != "$EXPECTED" ]]; then
  echo "ERROR: HEC stream contains $LINES lines but manifest expects $EXPECTED events." >&2
  exit 2
fi

# Refuse to ingest unless the HEC-envelope parser is active. Without this,
# Splunk would timestamp the wrapper at index time and the exercise would be
# corrupted silently.
if ! /opt/splunk/bin/splunk btool props list asteron:hec --debug 2>/dev/null \
    | grep -Eq 'INDEXED_EXTRACTIONS\s*=\s*HEC'; then
  cat >&2 <<'MSG'
ERROR: [asteron:hec] INDEXED_EXTRACTIONS=HEC is not active.
Install splunk/app/TA-asteron-v3 into $SPLUNK_HOME/etc/apps/TA-asteron-v3
and restart Splunk before loading this dataset.
MSG
  exit 3
fi

echo "Loading $EXPECTED canonical events into index=$INDEX"
/opt/splunk/bin/splunk add oneshot "$HEC_FILE" \
  -index "$INDEX" \
  -host "ASTERON-INGEST" \
  -rename-source "asteron:hec:validation" \
  -sourcetype "asteron:hec"

echo
echo "Submitted $EXPECTED events. Splunk indexing is asynchronous; verify after the indexing queue drains."
echo "Expected event count: $EXPECTED"
