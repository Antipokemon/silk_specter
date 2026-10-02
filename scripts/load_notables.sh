#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-easy}"
SOURCE_INDEX="${2:-}"
NOTABLE_INDEX="${3:-${NOTABLE_INDEX:-notable}}"
CONTAINER="${SPLUNK_CONTAINER:-splunk}"
CFG="$ROOT/config/scenarios/$SCENARIO.json"
DATA="$ROOT/dataset/$SCENARIO/notables"
REMOTE="/tmp/silk-specter-notables-$SCENARIO"

if [[ ! -f "$CFG" ]]; then
  echo "Unknown scenario: $SCENARIO" >&2
  exit 2
fi
if [[ -z "$SOURCE_INDEX" ]]; then
  SOURCE_INDEX="$(python3 - "$CFG" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['index'])
PY
)"
fi
if [[ ! -f "$DATA/hec/events.jsonl" || ! -f "$DATA/manifest.json" ]]; then
  echo "Notable dataset missing under $DATA. Generate the track first." >&2
  exit 3
fi

EXPECTED="$(python3 - "$DATA/manifest.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['events'])
PY
)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/hec"
cp "$DATA/manifest.json" "$TMP/manifest.json"
python3 - "$DATA/hec/events.jsonl" "$TMP/hec/events.jsonl" "$SOURCE_INDEX" <<'PY'
import json,sys
src,dst,index=sys.argv[1:4]
with open(src,encoding='utf-8') as fin, open(dst,'w',encoding='utf-8',newline='\n') as fout:
    for line in fin:
        if not line.strip():
            continue
        row=json.loads(line)
        row['event']=str(row.get('event','')).replace('<index>',index)
        fout.write(json.dumps(row,separators=(',',':'))+'\n')
PY

if ! podman exec --user splunk "$CONTAINER" /opt/splunk/bin/splunk list index 2>/dev/null \
    | grep -Eq "(^|[[:space:]])${NOTABLE_INDEX}([[:space:]]|$)"; then
  if [[ "${CREATE_NOTABLE_INDEX:-0}" == "1" ]]; then
    echo "Creating notable index: $NOTABLE_INDEX"
    podman exec --user splunk "$CONTAINER" /opt/splunk/bin/splunk add index "$NOTABLE_INDEX"
  else
    echo "ERROR: notable index '$NOTABLE_INDEX' does not exist." >&2
    echo "Splunk ES normally provides index=notable." >&2
    echo "For a non-ES lab, choose another index or rerun with CREATE_NOTABLE_INDEX=1." >&2
    exit 4
  fi
fi

podman exec --user 0 "$CONTAINER" rm -rf "$REMOTE"
podman cp "$TMP" "$CONTAINER:$REMOTE"
podman cp "$ROOT/splunk/ingest/load_hec.sh" "$CONTAINER:$REMOTE/load_hec.sh"
podman exec --user 0 "$CONTAINER" chmod 755 "$REMOTE/load_hec.sh"

podman exec --user splunk "$CONTAINER" bash "$REMOTE/load_hec.sh" "$REMOTE" "$NOTABLE_INDEX"

echo
echo "Submitted $EXPECTED synthetic notables for track=$SCENARIO to index=$NOTABLE_INDEX."
echo "Validate with:"
echo "  index=$NOTABLE_INDEX source=notable sourcetype=stash scenario=$SCENARIO | stats count by rule_name urgency"
