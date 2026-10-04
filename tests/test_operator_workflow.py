import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


FAKE_PODMAN = r'''#!/usr/bin/env bash
set -u
if [[ -n "${FAKE_PODMAN_LOG:-}" ]]; then
  printf '%s\n' "$*" >> "$FAKE_PODMAN_LOG"
fi
args="$*"

if [[ "${1:-}" == "cp" ]]; then
  exit 0
fi

if [[ "${1:-}" == "restart" ]]; then
  rc="${FAKE_RESTART_RC:-0}"
  if [[ "$rc" != "0" ]]; then
    echo "simulated restart warning" >&2
    exit "$rc"
  fi
  exit 0
fi

if [[ "${1:-}" == "inspect" ]]; then
  if [[ "$args" == *".State.Running"* ]]; then
    echo true
  elif [[ "$args" == *".State.Health.Status"* ]]; then
    echo healthy
  else
    echo '{}'
  fi
  exit 0
fi

if [[ "${1:-}" == "logs" ]]; then
  echo "simulated container log"
  exit 0
fi

if [[ "${1:-}" == "top" ]]; then
  echo "PID ARGS"
  echo "1459 splunkd --under-systemd"
  exit 0
fi

if [[ "${1:-}" == "exec" ]]; then
  if [[ "$args" == *"btool indexes list --debug"* ]]; then
    echo '[main]'
    exit 0
  fi
  if [[ "$args" == *"btool indexes list"* && "$args" == *"--debug"* ]]; then
    echo 'homePath = $SPLUNK_DB/test/db'
    echo 'coldPath = $SPLUNK_DB/test/colddb'
    echo 'thawedPath = $SPLUNK_DB/test/thaweddb'
    exit 0
  fi
  if [[ "$args" == *"btool indexes list"* ]]; then
    echo '[main]'
    if [[ "${FAKE_INDEX_EXISTS:-0}" == "1" ]]; then
      echo "[${FAKE_INDEX_NAME:-test_easy_v001}]"
    fi
    exit 0
  fi
  if [[ "$args" == *"btool props list asteron:hec"* ]]; then
    echo 'INDEXED_EXTRACTIONS = HEC'
    exit 0
  fi
  if [[ "$args" == *"PREEXISTING_INDEX_DATA_CHECK"* ]]; then
    if [[ "${FAKE_PREEXISTING_INDEX_DATA:-0}" == "1" ]]; then
      echo "/opt/splunk/var/lib/splunk/test/db/db_1_1_0/rawdata/journal.zst"
      exit 0
    fi
    exit 1
  fi
  if [[ "$args" == *"test -d"* ]]; then
    # Legacy compatibility for older test paths.
    exit 1
  fi
  if [[ "$args" == *"test ! -e"* ]]; then
    # Simulate the batch input having consumed the copied HEC stream.
    exit 0
  fi
  if [[ "$args" == *"POSTINGEST_INDEX_DATA_CHECK"* ]]; then
    echo "/opt/splunk/var/lib/splunk/test/db/hot_v1_1/rawdata/journal.zst"
    exit 0
  fi
  exit 0
fi

exit 0
'''


class OperatorWorkflowTests(unittest.TestCase):
    def test_loader_shell_syntax(self):
        for rel in ("scripts/load_to_splunk.sh", "scripts/load_notables.sh"):
            subprocess.run(["bash", "-n", str(ROOT / rel)], check=True)

    def _fake_podman_env(self, bindir):
        podman = bindir / "podman"
        podman.write_text(FAKE_PODMAN, encoding="utf-8")
        podman.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env['PATH']}"
        env["SPLUNK_CONTAINER"] = "fake-splunk"
        env["SPLUNK_READY_TIMEOUT"] = "2"
        env["SPLUNK_INGEST_TIMEOUT"] = "2"
        return env

    def _make_loader_fixture(self, root, track):
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "config/scenarios").mkdir(parents=True, exist_ok=True)
        (root / f"dataset/{track}/hec").mkdir(parents=True, exist_ok=True)
        (root / "splunk/app/TA-asteron-v3").mkdir(parents=True, exist_ok=True)

        shutil.copy2(ROOT / "scripts/load_to_splunk.sh", root / "scripts/load_to_splunk.sh")

        status = "validated" if track == "easy" else "authoring"
        (root / f"config/scenarios/{track}.json").write_text(
            json.dumps({"status": status, "index": f"asteron_{track}"}),
            encoding="utf-8",
        )
        (root / f"dataset/{track}/manifest.json").write_text(
            json.dumps({"events": 1}), encoding="utf-8"
        )
        event = {
            "time": 1790899200.0,
            "host": "TEST-HOST",
            "source": "test",
            "sourcetype": "XmlWinEventLog:Security",
            "event": "test event",
        }
        (root / f"dataset/{track}/hec/events.jsonl").write_text(
            json.dumps(event, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def test_loader_accepts_all_tracks_without_network_ports_or_cli_auth(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bindir = td / "bin"
            bindir.mkdir()
            env = self._fake_podman_env(bindir)

            for track in ("easy", "medium", "hard"):
                fixture = td / f"repo-{track}"
                self._make_loader_fixture(fixture, track)
                load_env = env.copy()
                if track != "easy":
                    load_env["ALLOW_AUTHORING"] = "1"

                proc = subprocess.run(
                    [str(fixture / "scripts/load_to_splunk.sh"), track, f"test_{track}_v001"],
                    cwd=fixture,
                    env=load_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("No host-published Splunk management or HEC port was used.", proc.stdout)

    def test_loader_has_no_rest_hec_or_interactive_cli_dependency(self):
        text = (ROOT / "scripts/load_to_splunk.sh").read_text(encoding="utf-8")
        forbidden = (
            "splunk login",
            "splunk list index",
            "splunk add index",
            "splunk add oneshot",
            "127.0.0.1:8089",
            "127.0.0.1:8088",
            "/services/data/indexes",
        )
        for value in forbidden:
            self.assertNotIn(value, text)
        self.assertIn("podman cp", text)
        self.assertIn("btool indexes list", text)
        self.assertIn("batch://", text)
        self.assertIn("move_policy = sinkhole", text)
        self.assertIn("/opt/splunk/var/spool/silk-specter-", text)
        self.assertNotIn('REMOTE="/tmp/silk-specter-', text)

    def test_loader_uses_container_health_and_batch_consumption_as_gates(self):
        text = (ROOT / "scripts/load_to_splunk.sh").read_text(encoding="utf-8")
        self.assertIn(".State.Health.Status", text)
        self.assertIn("wait_for_batch_consumption", text)
        self.assertIn("wait_for_index_data", text)
        self.assertIn('test ! -e "$HEC_REMOTE"', text)
        self.assertIn("rawdata/journal.*", text)
        self.assertNotIn("rawdata/journal.gz", text)
        self.assertIn("SPLUNK_READY_TIMEOUT:-300", text)
        self.assertIn("SPLUNK_INGEST_TIMEOUT:-600", text)


    def test_existing_empty_index_is_reused(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bindir = td / "bin"
            bindir.mkdir()
            env = self._fake_podman_env(bindir)
            env["FAKE_INDEX_EXISTS"] = "1"
            env["FAKE_INDEX_NAME"] = "test_easy_v001"
            fixture = td / "repo-easy"
            self._make_loader_fixture(fixture, "easy")

            proc = subprocess.run(
                [str(fixture / "scripts/load_to_splunk.sh"), "easy", "test_easy_v001"],
                cwd=fixture,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn(
                "Index test_easy_v001 already exists but contains no raw bucket data; reusing it.",
                proc.stdout,
            )

    def test_existing_index_with_data_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bindir = td / "bin"
            bindir.mkdir()
            env = self._fake_podman_env(bindir)
            env["FAKE_INDEX_EXISTS"] = "1"
            env["FAKE_INDEX_NAME"] = "test_easy_v001"
            env["FAKE_PREEXISTING_INDEX_DATA"] = "1"
            fixture = td / "repo-easy"
            self._make_loader_fixture(fixture, "easy")

            proc = subprocess.run(
                [str(fixture / "scripts/load_to_splunk.sh"), "easy", "test_easy_v001"],
                cwd=fixture,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 6, proc.stdout)
            self.assertIn(
                "index test_easy_v001 already contains indexed data",
                proc.stdout,
            )

    def test_nonzero_restart_is_tolerated_if_container_recovers(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bindir = td / "bin"
            bindir.mkdir()
            env = self._fake_podman_env(bindir)
            env["FAKE_RESTART_RC"] = "125"
            fixture = td / "repo-easy"
            self._make_loader_fixture(fixture, "easy")

            proc = subprocess.run(
                [str(fixture / "scripts/load_to_splunk.sh"), "easy", "test_easy_restart_v001"],
                cwd=fixture,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("podman restart returned rc=125", proc.stdout)

    def test_loader_copies_ingest_file_after_restart_and_uses_atomic_rename(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bindir = td / "bin"
            bindir.mkdir()
            env = self._fake_podman_env(bindir)
            log = td / "podman.log"
            env["FAKE_PODMAN_LOG"] = str(log)
            fixture = td / "repo-easy"
            self._make_loader_fixture(fixture, "easy")

            proc = subprocess.run(
                [str(fixture / "scripts/load_to_splunk.sh"), "easy", "test_easy_copy_v001"],
                cwd=fixture,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            commands = log.read_text(encoding="utf-8")

            self.assertIn(
                "splunk/app/TA-asteron-v3/. fake-splunk:/opt/splunk/etc/apps/TA-asteron-v3",
                commands,
            )
            self.assertIn(
                "fake-splunk:/opt/splunk/etc/apps/SA-silk-specter-easy-test_easy_copy_v001",
                commands,
            )
            self.assertIn(
                "fake-splunk:/opt/splunk/var/spool/silk-specter-easy-test_easy_copy_v001/events.jsonl.upload",
                commands,
            )
            self.assertIn(
                "mv /opt/splunk/var/spool/silk-specter-easy-test_easy_copy_v001/events.jsonl.upload "
                "/opt/splunk/var/spool/silk-specter-easy-test_easy_copy_v001/events.jsonl",
                commands,
            )

            restart_pos = commands.index("restart --time")
            upload_pos = commands.index("events.jsonl.upload")
            self.assertLess(restart_pos, upload_pos, commands)



if __name__ == "__main__":
    unittest.main()
