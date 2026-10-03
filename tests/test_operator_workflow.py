import os
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

if [[ "${1:-}" == "restart" ]]; then
  rc="${FAKE_RESTART_RC:-0}"
  if [[ "$rc" != "0" ]]; then
    echo "simulated restart warning" >&2
    exit "$rc"
  fi
  exit 0
fi

if [[ "${1:-}" == "inspect" ]]; then
  if [[ "${FAKE_SPLUNK_READY:-1}" == "1" ]]; then
    echo true
  else
    echo false
  fi
  exit 0
fi

if [[ "${1:-}" == "logs" ]]; then
  echo "simulated container log"
  exit 0
fi

if [[ "${1:-}" == "top" ]]; then
  if [[ "${FAKE_SPLUNK_READY:-1}" == "1" ]]; then
    echo "PID ARGS"
    echo "1459 splunkd --under-systemd"
    exit 0
  fi
  echo "PID ARGS"
  exit 0
fi

if [[ "$args" == *"btool props list asteron:hec"* ]]; then
  echo 'INDEXED_EXTRACTIONS = HEC'
  exit 0
fi
if [[ "$args" == *"/opt/splunk/bin/splunk status"* ]]; then
  if [[ "${FAKE_SPLUNK_READY:-1}" == "1" ]]; then
    echo 'splunkd is running'
    exit 0
  fi
  echo 'splunkd is not running'
  exit 1
fi
if [[ "$args" == *"/opt/splunk/bin/splunk list index"* ]]; then
  echo 'notable'
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
        return env

    def test_loaders_accept_all_tracks_with_fake_podman(self):
        with tempfile.TemporaryDirectory() as td:
            bindir = Path(td)
            env = self._fake_podman_env(bindir)

            for track in ("easy", "medium", "hard"):
                load_env = env.copy()
                if track != "easy":
                    load_env["ALLOW_AUTHORING"] = "1"
                subprocess.run(
                    [str(ROOT / "scripts/load_to_splunk.sh"), track, f"test_{track}_v001"],
                    cwd=ROOT,
                    env=load_env,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                subprocess.run(
                    [str(ROOT / "scripts/load_notables.sh"), track, f"test_{track}_v001", "notable"],
                    cwd=ROOT,
                    env=env,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

    def test_load_survives_nonzero_podman_restart_if_splunk_recovers(self):
        with tempfile.TemporaryDirectory() as td:
            bindir = Path(td)
            env = self._fake_podman_env(bindir)
            log = bindir / "podman.log"
            env["FAKE_PODMAN_LOG"] = str(log)
            env["FAKE_RESTART_RC"] = "125"
            env["FAKE_SPLUNK_READY"] = "1"
            env["SPLUNK_READY_TIMEOUT"] = "2"

            proc = subprocess.run(
                [str(ROOT / "scripts/load_to_splunk.sh"), "easy", "test_easy_restart_v001"],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("podman restart returned rc=125", proc.stdout)
            commands = log.read_text(encoding="utf-8")
            self.assertIn("restart --time 60 fake-splunk", commands)
            self.assertIn("inspect --format {{.State.Running}} fake-splunk", commands)

    def test_restart_readiness_does_not_use_blocking_splunk_status(self):
        text = (ROOT / "scripts/load_to_splunk.sh").read_text(encoding="utf-8")
        wait_block = text.split("wait_for_splunk() {", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("/opt/splunk/bin/splunk status", wait_block)
        self.assertIn('podman top "$CONTAINER" pid args', wait_block)
        self.assertIn('timeout --signal=TERM --kill-after=1s', text)


    def test_loader_uses_noninteractive_container_credentials(self):
        text = (ROOT / "scripts/load_to_splunk.sh").read_text(encoding="utf-8")
        self.assertNotIn("/opt/splunk/bin/splunk login", text)
        self.assertIn("SPLUNK_PASSWORD", text)
        self.assertIn("-auth", text)
        self.assertIn("splunk_cli list index", text)
        self.assertIn("splunk_cli add index", text)

    def test_ta_install_replaces_destination_instead_of_nesting(self):
        with tempfile.TemporaryDirectory() as td:
            bindir = Path(td)
            env = self._fake_podman_env(bindir)
            log = bindir / "podman.log"
            env["FAKE_PODMAN_LOG"] = str(log)

            subprocess.run(
                [str(ROOT / "scripts/load_to_splunk.sh"), "easy", "test_easy_ta_v001"],
                cwd=ROOT,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            commands = log.read_text(encoding="utf-8")
            self.assertIn(
                "exec --user 0 fake-splunk rm -rf /opt/splunk/etc/apps/TA-asteron-v3",
                commands,
            )
            self.assertIn(
                "exec --user 0 fake-splunk mkdir -p /opt/splunk/etc/apps/TA-asteron-v3",
                commands,
            )
            self.assertIn(
                "splunk/app/TA-asteron-v3/. fake-splunk:/opt/splunk/etc/apps/TA-asteron-v3",
                commands,
            )


if __name__ == "__main__":
    unittest.main()
