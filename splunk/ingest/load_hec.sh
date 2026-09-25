#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${1:-/tmp/silk-specter-v3-easy}"
INDEX="${2:-asteron_easy_v030}"
HEC_FILE="$DATA_DIR/hec/events.jsonl"
MANIFEST="$DATA_DIR/manifest.json"
MAPPED_HEC="$(mktemp /tmp/asteron-hec-corelight.XXXXXX.jsonl)"
trap 'rm -f "$MAPPED_HEC"' EXIT

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

# Backward-compatible metadata remap. v0.2+ generators already emit Corelight
# sourcetypes, but this also permits loading older HEC streams without touching
# the source-native event payload in the "event" field.
python3 - "$HEC_FILE" "$MAPPED_HEC" <<'PY'
import collections,json,sys
src,dst=sys.argv[1:3]
SOURCETYPE_MAP={
    'zeek:conn':'bro:conn:json',
    'zeek:dns':'bro:dns:json',
    'zeek:http':'bro:http:json',
    'zeek:tls':'bro:ssl:json',
    'zeek:ssl':'bro:ssl:json',
    'zeek:smb_files':'bro:smb_files:json',
    'zeek:dce_rpc':'bro:dce_rpc:json',
    'zeek:files':'bro:files:json',
    'zeek:x509':'bro:x509:json',
}
after=collections.Counter(); changed=0
with open(src,encoding='utf-8') as fin, open(dst,'w',encoding='utf-8',newline='\n') as fout:
    for line in fin:
        if not line.strip():
            continue
        obj=json.loads(line)
        old=obj.get('sourcetype','')
        new=SOURCETYPE_MAP.get(old,old)
        if new != old:
            obj['sourcetype']=new
            changed+=1
        after[new]+=1
        fout.write(json.dumps(obj,separators=(',',':'))+'\n')
legacy=set(SOURCETYPE_MAP)
remaining=sorted(st for st in after if st in legacy)
if remaining:
    raise SystemExit('ERROR: legacy Zeek sourcetypes remain: '+', '.join(remaining))
print(f'Prepared {sum(after.values())} events; remapped {changed} legacy Zeek metadata records.')
for st in sorted(after):
    if st.startswith('bro:'):
        print(f'  {st}: {after[st]}')
PY

MAPPED_LINES="$(wc -l < "$MAPPED_HEC" | tr -d ' ')"
if [[ "$MAPPED_LINES" != "$EXPECTED" ]]; then
  echo "ERROR: mapped HEC stream contains $MAPPED_LINES lines but expected $EXPECTED." >&2
  exit 3
fi

if ! /opt/splunk/bin/splunk btool props list asteron:hec --debug 2>/dev/null \
    | grep -Eq 'INDEXED_EXTRACTIONS\s*=\s*HEC'; then
  cat >&2 <<'MSG'
ERROR: [asteron:hec] INDEXED_EXTRACTIONS=HEC is not active.
Install splunk/app/TA-asteron-v3 into $SPLUNK_HOME/etc/apps/TA-asteron-v3
and restart Splunk before loading this dataset.
MSG
  exit 4
fi

echo "Loading $EXPECTED canonical events into index=$INDEX"
/opt/splunk/bin/splunk add oneshot "$MAPPED_HEC" \
  -index "$INDEX" \
  -host "ASTERON-INGEST" \
  -rename-source "asteron:hec:validation" \
  -sourcetype "asteron:hec"

echo
echo "Submitted $EXPECTED events to index=$INDEX."
echo "The temporary remap file was written under /tmp and will be deleted automatically."
echo "Use a fresh index; already-indexed events retain their previous metadata."
