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
REST_TIMEOUT="${SPLUNK_REST_TIMEOUT:-15}"
REST_COMMAND_TIMEOUT="${SPLUNK_REST_COMMAND_TIMEOUT:-20}"

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

splunk_rest() {
  local action="$1"
  timeout --signal=TERM --kill-after=2s "${REST_COMMAND_TIMEOUT}s" \
    podman exec --user splunk \
      --env "SILK_SPLUNK_CLI_USER=$SPLUNK_CLI_USER" \
      --env "SILK_SPLUNK_INDEX=$INDEX" \
      --env "SILK_SPLUNK_REST_TIMEOUT=$REST_TIMEOUT" \
      --env "SILK_SPLUNK_REST_ACTION=$action" \
      "$CONTAINER" bash -lc '
        if [[ -z "${SPLUNK_PASSWORD:-}" ]]; then
          echo "ERROR:SPLUNK_PASSWORD_MISSING"
          exit 86
        fi
        if ! command -v curl >/dev/null 2>&1; then
          echo "ERROR:CURL_MISSING"
          exit 87
        fi
        common=(
          -skS
          --connect-timeout 5
          --max-time "$SILK_SPLUNK_REST_TIMEOUT"
          -u "${SILK_SPLUNK_CLI_USER}:${SPLUNK_PASSWORD}"
          -o /dev/null
          -w "%{http_code}"
        )
        case "$SILK_SPLUNK_REST_ACTION" in
          check)
            exec curl "${common[@]}" \
              "https://127.0.0.1:8089/services/data/indexes/${SILK_SPLUNK_INDEX}?output_mode=json"
            ;;
          create)
            exec curl "${common[@]}" \
              -X POST \
              --data-urlencode "name=${SILK_SPLUNK_INDEX}" \
              "https://127.0.0.1:8089/services/data/indexes?output_mode=json"
            ;;
          *)
            echo "ERROR:UNKNOWN_REST_ACTION"
            exit 88
            ;;
        esac
      '
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

echo "[1/7] Installing/updating TA-asteron-v3 in container=$CONTAINER"
# Remove the existing destination first. Copying a source directory onto an
# existing destination directory can create a nested TA-asteron-v3/TA-asteron-v3.
podman exec --user 0 "$CONTAINER" rm -rf "$TA_DST"
podman exec --user 0 "$CONTAINER" mkdir -p "$TA_DST"
podman cp "$TA_SRC/." "$CONTAINER:$TA_DST"
podman exec --user 0 "$CONTAINER" chown -R splunk:splunk "$TA_DST"

echo "[2/7] Restarting Splunk container (stop timeout=${RESTART_TIMEOUT}s)"
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

echo "[3/7] Verifying [asteron:hec] INDEXED_EXTRACTIONS=HEC"
if ! podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool props list asteron:hec --debug 2>/dev/null \
    | grep -Eq 'INDEXED_EXTRACTIONS\s*=\s*HEC'; then
  echo "ERROR: TA-asteron-v3 parser is not active after restart." >&2
  echo "Check: podman exec --user splunk $CONTAINER /opt/splunk/bin/splunk btool props list asteron:hec --debug" >&2
  exit 5
fi

echo "[4/7] Verifying REST credentials and fresh index name: $INDEX"
echo "      REST timeout=${REST_TIMEOUT}s; podman command timeout=${REST_COMMAND_TIMEOUT}s"
REST_RESULT="$(mktemp)"
trap 'rm -f "$REST_RESULT"' EXIT

set +e
splunk_rest check >"$REST_RESULT" 2>&1
rest_rc=$?
set -e
INDEX_HTTP_CODE="$(tr -d '\r\n' <"$REST_RESULT")"

if (( rest_rc != 0 )); then
  echo "ERROR: Splunk REST index check failed or timed out (rc=$rest_rc)." >&2
  cat "$REST_RESULT" >&2
  echo >&2
  echo "Check port 8089 directly with:" >&2
  echo "  podman exec --user splunk $CONTAINER curl -sk --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}\\n' https://127.0.0.1:8089/services/server/info" >&2
  exit 6
fi

case "$INDEX_HTTP_CODE" in
  200)
    echo "ERROR: index $INDEX already exists. Use a fresh index name." >&2
    exit 7
    ;;
  404)
    ;;
  401|403)
    echo "ERROR: Splunk REST authentication failed (HTTP $INDEX_HTTP_CODE)." >&2
    exit 6
    ;;
  *)
    echo "ERROR: unexpected HTTP response while checking index $INDEX: $INDEX_HTTP_CODE" >&2
    exit 6
    ;;
esac

echo "      Creating index $INDEX through splunkd REST"
: >"$REST_RESULT"
set +e
splunk_rest create >"$REST_RESULT" 2>&1
create_rc=$?
set -e
CREATE_HTTP_CODE="$(tr -d '\r\n' <"$REST_RESULT")"

if (( create_rc != 0 )); then
  echo "ERROR: Splunk REST index creation failed or timed out (rc=$create_rc)." >&2
  cat "$REST_RESULT" >&2
  exit 6
fi

case "$CREATE_HTTP_CODE" in
  200|201)
    echo "      Index created (HTTP $CREATE_HTTP_CODE)."
    ;;
  *)
    echo "ERROR: index creation returned HTTP $CREATE_HTTP_CODE." >&2
    exit 6
    ;;
esac

rm -f "$REST_RESULT"
trap - EXIT

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
