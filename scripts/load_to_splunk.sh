#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-easy}"
INDEX="${2:-}"
CONTAINER="${SPLUNK_CONTAINER:-splunk}"
CFG="$ROOT/config/scenarios/$SCENARIO.json"
DATA="$ROOT/dataset/$SCENARIO"
REMOTE="/tmp/silk-specter-v3-$SCENARIO"
TA_SRC="$ROOT/splunk/app/TA-asteron-v3"
TA_DST="/opt/splunk/etc/apps/TA-asteron-v3"
RESTART_TIMEOUT="${SPLUNK_RESTART_TIMEOUT:-60}"
READY_TIMEOUT="${SPLUNK_READY_TIMEOUT:-120}"
PROBE_TIMEOUT="${SPLUNK_READY_PROBE_TIMEOUT:-5}"
SPLUNK_CLI_USER="${SPLUNK_CLI_USER:-admin}"

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

bounded() {
  # Bound Podman probes so a wedged container/runtime cannot trap the loader.
  timeout --signal=TERM --kill-after=1s "${PROBE_TIMEOUT}s" "$@"
}

splunk_cli() {
  # Run authenticated Splunk CLI commands without `splunk login`. The password
  # remains inside the container environment and is not expanded into the host
  # process list or shell history.
  podman exec --user splunk \
    --env "SILK_SPLUNK_CLI_USER=$SPLUNK_CLI_USER" \
    "$CONTAINER" bash -lc '
      if [[ -z "${SPLUNK_PASSWORD:-}" ]]; then
        echo "ERROR: SPLUNK_PASSWORD is not set in the running Splunk container." >&2
        exit 86
      fi
      exec /opt/splunk/bin/splunk "$@" \
        -auth "${SILK_SPLUNK_CLI_USER}:${SPLUNK_PASSWORD}"
    ' _ "$@"
}

wait_for_splunk() {
  local started=$SECONDS
  local deadline=$((started + READY_TIMEOUT))
  local next_report=10
  local state_file="/tmp/silk-specter-state.$$"
  local top_file="/tmp/silk-specter-top.$$"

  while (( SECONDS < deadline )); do
    : >"$state_file"
    : >"$top_file"

    if bounded podman inspect --format '{{.State.Running}}' "$CONTAINER" \
        >"$state_file" 2>/dev/null \
        && grep -qx 'true' "$state_file"; then

      # Do not use `podman exec ... splunk status` as a readiness probe.
      # That command can block indefinitely while Splunk is recovering after a
      # container restart. `podman top` checks the container process list without
      # starting another process inside the container.
      if bounded podman top "$CONTAINER" pid args >"$top_file" 2>/dev/null \
          && grep -qiE '(^|[[:space:]/])splunkd([[:space:]]|$)' "$top_file"; then
        rm -f "$state_file" "$top_file"
        return 0
      fi
    fi

    if (( SECONDS - started >= next_report )); then
      echo "      Still waiting for splunkd ($((SECONDS - started))s elapsed) ..."
      next_report=$((next_report + 10))
    fi
    sleep 2
  done

  rm -f "$state_file" "$top_file"
  return 1
}

echo "[1/8] Installing/updating TA-asteron-v3 in container=$CONTAINER"
# Remove the existing destination first. Copying a source directory onto an
# existing destination directory can create a nested TA-asteron-v3/TA-asteron-v3.
podman exec --user 0 "$CONTAINER" rm -rf "$TA_DST"
podman exec --user 0 "$CONTAINER" mkdir -p "$TA_DST"
podman cp "$TA_SRC/." "$CONTAINER:$TA_DST"
podman exec --user 0 "$CONTAINER" chown -R splunk:splunk "$TA_DST"

echo "[2/8] Restarting Splunk container (stop timeout=${RESTART_TIMEOUT}s)"
# Podman may report a non-zero status when SIGTERM times out and it has to use
# SIGKILL, even though the container subsequently starts successfully. Do not
# let `set -e` abort here; verify the actual container/Splunk state instead.
restart_rc=0
podman restart --time "$RESTART_TIMEOUT" "$CONTAINER" >/dev/null || restart_rc=$?
if (( restart_rc != 0 )); then
  echo "WARNING: podman restart returned rc=$restart_rc; checking whether Splunk recovered." >&2
fi

echo "      Waiting up to ${READY_TIMEOUT}s for splunkd process (probe timeout=${PROBE_TIMEOUT}s) ..."
if ! wait_for_splunk; then
  echo "ERROR: Splunk did not become ready within ${READY_TIMEOUT}s after restart." >&2
  echo "Container state:" >&2
  podman inspect --format '{{.State.Status}}' "$CONTAINER" 2>/dev/null >&2 || true
  echo "Recent container logs:" >&2
  podman logs --tail 80 "$CONTAINER" 2>/dev/null >&2 || true
  exit 5
fi
echo "      splunkd is running."

echo "[3/8] Verifying [asteron:hec] INDEXED_EXTRACTIONS=HEC"
if ! podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool props list asteron:hec --debug 2>/dev/null \
    | grep -Eq 'INDEXED_EXTRACTIONS\s*=\s*HEC'; then
  echo "ERROR: TA-asteron-v3 parser is not active after restart." >&2
  echo "Check: podman exec --user splunk $CONTAINER /opt/splunk/bin/splunk btool props list asteron:hec --debug" >&2
  exit 5
fi

echo "[4/7] Verifying non-interactive Splunk CLI credentials and fresh index name: $INDEX"
set +e
INDEX_LIST="$(splunk_cli list index 2>&1)"
cli_rc=$?
set -e

if (( cli_rc != 0 )); then
  echo "ERROR: authenticated Splunk CLI check failed (rc=$cli_rc)." >&2
  echo "$INDEX_LIST" >&2
  echo >&2
  echo "The running container must provide SPLUNK_PASSWORD." >&2
  echo "Check with:" >&2
  echo "  podman inspect $CONTAINER --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^SPLUNK_PASSWORD='" >&2
  exit 6
fi

if grep -Eq "(^|[[:space:]])${INDEX}([[:space:]]|$)" <<<"$INDEX_LIST"; then
  echo "ERROR: index $INDEX already exists. Use a fresh index name." >&2
  exit 7
fi

echo "      Creating index $INDEX"
splunk_cli add index "$INDEX"

echo "[5/7] Copying dataset to $REMOTE"
podman exec --user 0 "$CONTAINER" rm -rf "$REMOTE"
podman cp "$DATA" "$CONTAINER:$REMOTE"
podman cp "$ROOT/splunk/ingest/load_hec.sh" "$CONTAINER:$REMOTE/load_hec.sh"
podman exec --user 0 "$CONTAINER" chmod 755 "$REMOTE/load_hec.sh"

echo "[6/7] Loading $EXPECTED events into $INDEX"
podman exec --user splunk "$CONTAINER" bash \
  "$REMOTE/load_hec.sh" "$REMOTE" "$INDEX"

echo "[7/7] Load submitted"
echo
echo "Expected event count: $EXPECTED"
echo "Validate in Splunk with:"
echo "  | tstats count where index=$INDEX"
echo "  index=$INDEX | stats count by sourcetype | sort sourcetype"
echo
echo "After validation you may remove: $REMOTE"
