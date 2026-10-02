#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-easy}"
INDEX="${2:-}"
CONTAINER="${SPLUNK_CONTAINER:-splunk}"
CFG="$ROOT/config/scenarios/$SCENARIO.json"
DATA="$ROOT/dataset/$SCENARIO"
REMOTE="/tmp/silk-specter-v3-$SCENARIO"

if [[ ! -f "$CFG" ]]; then
  echo "Unknown scenario: $SCENARIO" >&2
  exit 2
fi

readarray -t META < <(python3 - "$CFG" <<'PY'
import json,sys
x=json.load(open(sys.argv[1],encoding='utf-8'))
print(x.get('status','authoring'))
print(x['index'])
PY
)
STATUS="${META[0]}"
BASE_INDEX="${META[1]}"

if [[ "$STATUS" != "validated" && "${ALLOW_AUTHORING:-0}" != "1" ]]; then
  echo "Refusing to load scenario=$SCENARIO because status=$STATUS." >&2
  echo "For an explicit validation build, rerun with ALLOW_AUTHORING=1." >&2
  exit 3
fi
if [[ "$STATUS" != "validated" ]]; then
  echo "WARNING: loading authoring-status scenario=$SCENARIO for validation only." >&2
fi

if [[ -z "$INDEX" ]]; then
  INDEX="${BASE_INDEX}_v001"
fi

if [[ ! -f "$DATA/hec/events.jsonl" || ! -f "$DATA/manifest.json" ]]; then
  echo "Generated dataset missing under $DATA. Run generator/generate.py first." >&2
  exit 4
fi

EXPECTED="$(python3 - "$DATA/manifest.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['events'])
PY
)"

echo "[1/8] Installing/updating TA-asteron-v3 in container=$CONTAINER"
podman cp "$ROOT/splunk/app/TA-asteron-v3" \
  "$CONTAINER:/opt/splunk/etc/apps/TA-asteron-v3"

echo "[2/8] Restarting Splunk"
podman restart "$CONTAINER" >/dev/null

# Wait only for the local process to report running; this is not asynchronous work.
for _ in $(seq 1 30); do
  if podman exec --user splunk "$CONTAINER" \
      /opt/splunk/bin/splunk status 2>/dev/null | grep -qi 'splunkd is running'; then
    break
  fi
  sleep 1
done

echo "[3/8] Verifying [asteron:hec] INDEXED_EXTRACTIONS=HEC"
if ! podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool props list asteron:hec --debug 2>/dev/null \
    | grep -Eq 'INDEXED_EXTRACTIONS\s*=\s*HEC'; then
  echo "ERROR: TA-asteron-v3 parser is not active." >&2
  exit 5
fi

echo "[4/8] Splunk CLI login is required"
podman exec -it --user splunk "$CONTAINER" \
  /opt/splunk/bin/splunk login

echo "[5/8] Verifying fresh index name: $INDEX"
if podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk list index 2>/dev/null \
    | grep -Eq "(^|[[:space:]])${INDEX}([[:space:]]|$)"; then
  echo "ERROR: index $INDEX already exists. Use a fresh index name." >&2
  exit 6
fi

podman exec --user splunk "$CONTAINER" \
  /opt/splunk/bin/splunk add index "$INDEX"

echo "[6/8] Copying dataset to $REMOTE"
podman exec --user 0 "$CONTAINER" rm -rf "$REMOTE"
podman cp "$DATA" "$CONTAINER:$REMOTE"
podman cp "$ROOT/splunk/ingest/load_hec.sh" "$CONTAINER:$REMOTE/load_hec.sh"
podman exec --user 0 "$CONTAINER" chmod 755 "$REMOTE/load_hec.sh"

echo "[7/8] Loading $EXPECTED events into $INDEX"
podman exec --user splunk "$CONTAINER" bash \
  "$REMOTE/load_hec.sh" "$REMOTE" "$INDEX"

echo "[8/8] Load submitted"
echo
echo "Expected event count: $EXPECTED"
echo "Validate in Splunk with:"
echo "  | tstats count where index=$INDEX"
echo "  index=$INDEX | stats count by sourcetype | sort sourcetype"
echo
echo "After validation you may remove: $REMOTE"
