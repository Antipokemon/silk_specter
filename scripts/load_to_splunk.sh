#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-easy}"
INDEX="${2:-}"
CONTAINER="${SPLUNK_CONTAINER:-splunk}"
CFG="$ROOT/config/scenarios/$SCENARIO.json"
DATA="$ROOT/dataset/$SCENARIO"
TA_SRC="$ROOT/splunk/app/TA-asteron-v3"
TA_DST="/opt/splunk/etc/apps/TA-asteron-v3"
RESTART_TIMEOUT="${SPLUNK_RESTART_TIMEOUT:-60}"
READY_TIMEOUT="${SPLUNK_READY_TIMEOUT:-300}"
INGEST_TIMEOUT="${SPLUNK_INGEST_TIMEOUT:-600}"
PROBE_TIMEOUT="${SPLUNK_READY_PROBE_TIMEOUT:-5}"

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

# Keep the generated Splunk stanza, app path, and temporary path safe and simple.
if [[ ! "$INDEX" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
  echo "ERROR: index name contains unsupported characters: $INDEX" >&2
  echo "Use only letters, digits, underscore, and hyphen." >&2
  exit 2
fi

HEC_SRC="$DATA/hec/events.jsonl"
MANIFEST="$DATA/manifest.json"
if [[ ! -f "$HEC_SRC" || ! -f "$MANIFEST" ]]; then
  echo "Generated dataset missing under $DATA. Run the scenario generator first." >&2
  exit 4
fi

if [[ "$(head -n 1 "$HEC_SRC" 2>/dev/null || true)" == "version https://git-lfs.github.com/spec/v1" ]]; then
  echo "ERROR: $HEC_SRC is still a Git LFS pointer, not the dataset." >&2
  echo "Run 'git lfs pull' or regenerate the $SCENARIO dataset, then retry." >&2
  exit 4
fi

EXPECTED="$(python3 - "$MANIFEST" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['events'])
PY
)"

REMOTE="/opt/splunk/var/spool/silk-specter-${SCENARIO}-${INDEX}"
HEC_REMOTE="$REMOTE/events.jsonl"
HEC_UPLOAD="$REMOTE/events.jsonl.upload"
APP_NAME="SA-silk-specter-${SCENARIO}-${INDEX}"
APP_DST="/opt/splunk/etc/apps/$APP_NAME"

STAGE="$(mktemp -d /tmp/silk-specter-load.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT
PREPARED_HEC="$STAGE/events.jsonl"
APP_STAGE="$STAGE/$APP_NAME"
mkdir -p "$APP_STAGE/default" "$APP_STAGE/local"

bounded() {
  timeout --signal=TERM --kill-after=1s "${PROBE_TIMEOUT}s" "$@"
}

podman_exec_bounded() {
  bounded podman exec "$@"
}

wait_for_container() {
  local started=$SECONDS
  local deadline=$((started + READY_TIMEOUT))
  local next_report=10
  local running=""
  local health=""

  while (( SECONDS < deadline )); do
    running="$(bounded podman inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)"
    if [[ "$running" == "true" ]]; then
      health="$(bounded podman inspect --format '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || true)"
      case "$health" in
        healthy)
          return 0
          ;;
        starting|unhealthy)
          ;;
        *)
          # Some containers have no healthcheck. In that case, a running
          # splunkd process is enough to continue; batch ingestion below is the
          # final readiness gate and will wait until Splunk consumes the file.
          if bounded podman top "$CONTAINER" pid args 2>/dev/null \
              | grep -qiE '(^|[[:space:]/])splunkd([[:space:]]|$)'; then
            return 0
          fi
          ;;
      esac
    fi

    if (( SECONDS - started >= next_report )); then
      [[ -n "$health" ]] || health="unknown"
      echo "      Still waiting for container readiness ($((SECONDS - started))s elapsed; health=$health) ..."
      next_report=$((next_report + 10))
    fi
    sleep 2
  done

  return 1
}

wait_for_batch_consumption() {
  local started=$SECONDS
  local deadline=$((started + INGEST_TIMEOUT))
  local next_report=15

  while (( SECONDS < deadline )); do
    if bounded podman exec --user splunk "$CONTAINER" test ! -e "$HEC_REMOTE"; then
      return 0
    fi

    if (( SECONDS - started >= next_report )); then
      echo "      Still waiting for Splunk to consume the batch file ($((SECONDS - started))s elapsed) ..."
      next_report=$((next_report + 15))
    fi
    sleep 2
  done

  return 1
}

wait_for_index_data() {
  local started=$SECONDS
  local deadline=$((started + INGEST_TIMEOUT))
  local next_report=15

  while (( SECONDS < deadline )); do
    if bounded podman exec --user splunk --env "SILK_INDEX=$INDEX" "$CONTAINER" bash -lc '
      db="${SPLUNK_DB:-/opt/splunk/var/lib/splunk}/$SILK_INDEX/db"
      find "$db" -type f -path "*/rawdata/journal.gz" -size +0c -print -quit 2>/dev/null \
        | grep -q .
    '; then
      return 0
    fi

    if (( SECONDS - started >= next_report )); then
      echo "      Batch source is gone, but raw index data is not visible yet ($((SECONDS - started))s elapsed) ..."
      next_report=$((next_report + 15))
    fi
    sleep 2
  done

  return 1
}

echo "[1/8] Preflight: validating source data and fresh index=$INDEX"

# Make sure the container itself is available before mutating anything.
if ! bounded podman inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "ERROR: Splunk container '$CONTAINER' is not available." >&2
  exit 5
fi

# btool reads local configuration files only. It does not use splunkd REST,
# require a published management port, or require an interactive CLI login.
BTOOL_INDEXES="$STAGE/indexes.before"
set +e
bounded podman exec --user splunk "$CONTAINER" \
  /opt/splunk/bin/splunk btool indexes list >"$BTOOL_INDEXES" 2>&1
btool_rc=$?
set -e
if (( btool_rc != 0 )); then
  echo "ERROR: unable to read Splunk index configuration with btool (rc=$btool_rc)." >&2
  cat "$BTOOL_INDEXES" >&2
  exit 5
fi
if grep -Fqx "[$INDEX]" "$BTOOL_INDEXES"; then
  echo "ERROR: index $INDEX already exists in Splunk configuration. Use a fresh index name." >&2
  exit 6
fi

# Also reject a leftover data directory even if its stanza was removed.
set +e
bounded podman exec --user splunk --env "SILK_INDEX=$INDEX" "$CONTAINER" bash -lc \
  'db="${SPLUNK_DB:-/opt/splunk/var/lib/splunk}"; test -d "$db/$SILK_INDEX"'
data_dir_rc=$?
set -e
case "$data_dir_rc" in
  0)
    echo "ERROR: data directory for index $INDEX already exists. Use a fresh index name." >&2
    exit 6
    ;;
  1)
    ;;
  *)
    echo "ERROR: unable to verify whether index data directory exists (rc=$data_dir_rc)." >&2
    exit 5
    ;;
esac

# Prepare the canonical HEC envelope locally. This preserves the old Zeek ->
# Corelight metadata compatibility without invoking Splunk CLI or HEC over a
# network socket inside or outside the container.
python3 - "$HEC_SRC" "$PREPARED_HEC" "$EXPECTED" <<'PY'
import collections, json, sys
src, dst, expected_s = sys.argv[1:4]
expected = int(expected_s)
map_st = {
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
count = 0
changed = 0
seen = collections.Counter()
with open(src, encoding='utf-8') as fin, open(dst, 'w', encoding='utf-8', newline='\n') as fout:
    for lineno, line in enumerate(fin, 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f'ERROR: invalid HEC JSON at {src}:{lineno}: {exc}')
        old = obj.get('sourcetype', '')
        new = map_st.get(old, old)
        if new != old:
            obj['sourcetype'] = new
            changed += 1
        seen[new] += 1
        fout.write(json.dumps(obj, separators=(',', ':')) + '\n')
        count += 1
if count != expected:
    raise SystemExit(f'ERROR: HEC stream contains {count} events but manifest expects {expected}.')
legacy = sorted(st for st in seen if st in map_st)
if legacy:
    raise SystemExit('ERROR: legacy Zeek sourcetypes remain after remap: ' + ', '.join(legacy))
print(f'      Prepared {count} events; remapped {changed} legacy Zeek metadata records.')
PY

cat >"$APP_STAGE/default/app.conf" <<EOF_APP
[install]
is_configured = 1

[ui]
is_visible = 0

[launcher]
author = SILK SPECTER
description = Static loader configuration for $SCENARIO / $INDEX
version = 1.0.0
EOF_APP

cat >"$APP_STAGE/local/indexes.conf" <<EOF_INDEXES
[$INDEX]
homePath = \$SPLUNK_DB/$INDEX/db
coldPath = \$SPLUNK_DB/$INDEX/colddb
thawedPath = \$SPLUNK_DB/$INDEX/thaweddb
EOF_INDEXES

cat >"$APP_STAGE/local/inputs.conf" <<EOF_INPUTS
[batch://$HEC_REMOTE]
disabled = 0
index = $INDEX
sourcetype = asteron:hec
host = ASTERON-INGEST
move_policy = sinkhole
EOF_INPUTS

echo "[2/8] Copying TA-asteron-v3 and static loader app into container=$CONTAINER"
podman exec --user 0 "$CONTAINER" rm -rf "$TA_DST" "$APP_DST" "$REMOTE"
podman exec --user 0 "$CONTAINER" mkdir -p "$TA_DST" "$APP_DST" "$REMOTE"
podman cp "$TA_SRC/." "$CONTAINER:$TA_DST"
podman cp "$APP_STAGE/." "$CONTAINER:$APP_DST"
podman exec --user 0 "$CONTAINER" chown -R splunk:splunk "$TA_DST" "$APP_DST" "$REMOTE"

echo "[3/8] Restarting Splunk container (stop timeout=${RESTART_TIMEOUT}s)"
restart_rc=0
podman restart --time "$RESTART_TIMEOUT" "$CONTAINER" >/dev/null || restart_rc=$?
if (( restart_rc != 0 )); then
  echo "WARNING: podman restart returned rc=$restart_rc; waiting for container recovery." >&2
fi

echo "[4/8] Waiting up to ${READY_TIMEOUT}s for container health (no port checks)"
if ! wait_for_container; then
  echo "ERROR: Splunk container did not become ready within ${READY_TIMEOUT}s." >&2
  echo "Container state:" >&2
  podman inspect --format '{{.State.Status}} {{.State.Health.Status}}' "$CONTAINER" 2>/dev/null >&2 || true
  echo "Recent container logs:" >&2
  podman logs --tail 100 "$CONTAINER" 2>/dev/null >&2 || true
  exit 7
fi
echo "      Container is ready."

echo "[5/8] Verifying effective Splunk configuration with btool"
if ! bounded podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool props list asteron:hec --debug 2>/dev/null \
    | grep -Eq 'INDEXED_EXTRACTIONS\s*=\s*HEC'; then
  echo "ERROR: TA-asteron-v3 parser is not active after restart." >&2
  exit 8
fi

INDEX_CFG="$STAGE/index.after"
set +e
bounded podman exec --user splunk "$CONTAINER" \
  /opt/splunk/bin/splunk btool indexes list "$INDEX" --debug >"$INDEX_CFG" 2>&1
index_cfg_rc=$?
set -e
if (( index_cfg_rc != 0 )) || ! grep -Eq 'homePath\s*=' "$INDEX_CFG"; then
  echo "ERROR: index stanza [$INDEX] is not active after restart." >&2
  cat "$INDEX_CFG" >&2
  exit 8
fi

# Do not stage the ingest file before restart. Container /tmp may be ephemeral,
# and even other writable paths can be reset by image startup logic. Put the
# final data into Splunk's own var/spool tree only after Splunk is healthy.
#
# Copy to an unwatched temporary name, then atomically rename it so Splunk's
# batch input never sees a partially copied file.
echo "[6/8] Copying $EXPECTED prepared events into the live container"
podman exec --user 0 "$CONTAINER" mkdir -p "$REMOTE"
podman exec --user 0 "$CONTAINER" rm -f "$HEC_UPLOAD" "$HEC_REMOTE"
podman cp "$PREPARED_HEC" "$CONTAINER:$HEC_UPLOAD"
podman exec --user 0 "$CONTAINER" chown splunk:splunk "$HEC_UPLOAD"
podman exec --user 0 "$CONTAINER" mv "$HEC_UPLOAD" "$HEC_REMOTE"

echo "[7/8] Waiting for Splunk to consume the batch source"
echo "      Ingest timeout=${INGEST_TIMEOUT}s; no HEC or management port is required."
if ! wait_for_batch_consumption; then
  echo "ERROR: Splunk did not consume $HEC_REMOTE within ${INGEST_TIMEOUT}s." >&2
  echo "Effective input stanza:" >&2
  podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool inputs list --debug 2>/dev/null \
    | grep -A10 -B2 -F "$HEC_REMOTE" >&2 || true
  echo "Relevant splunkd.log entries:" >&2
  podman exec --user splunk "$CONTAINER" \
    grep -F "$HEC_REMOTE" /opt/splunk/var/log/splunk/splunkd.log 2>/dev/null >&2 || true
  exit 9
fi

echo "[8/8] Verifying that the target index contains raw bucket data"
if ! wait_for_index_data; then
  echo "ERROR: Splunk consumed the source file, but no raw index data appeared in $INDEX within ${INGEST_TIMEOUT}s." >&2
  echo "Relevant splunkd.log entries:" >&2
  podman exec --user splunk "$CONTAINER" bash -lc \
    "grep -Ei '$INDEX|asteron:hec|silk-specter-${SCENARIO}-${INDEX}' /opt/splunk/var/log/splunk/splunkd.log | tail -200" \
    2>/dev/null >&2 || true
  exit 10
fi

echo "      Raw index data is present."
echo
echo "Expected event count: $EXPECTED"
echo "Index: $INDEX"
echo "Loader app: $APP_DST"
echo "No host-published Splunk management or HEC port was used."
echo
echo "Validate the exact count in Splunk Web with:"
echo "  | tstats count where index=$INDEX"
echo "  index=$INDEX | stats count by sourcetype | sort sourcetype"
echo
echo "The batch source was sinkholed after Splunk read it. The staging directory"
echo "can be removed after validation:"
echo "  podman exec --user 0 $CONTAINER rm -rf $REMOTE"
