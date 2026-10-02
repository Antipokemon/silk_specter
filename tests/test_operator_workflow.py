import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class OperatorWorkflowTests(unittest.TestCase):
    def test_loader_shell_syntax(self):
        for rel in ("scripts/load_to_splunk.sh", "scripts/load_notables.sh"):
            subprocess.run(["bash", "-n", str(ROOT / rel)], check=True)

    def test_loaders_accept_all_tracks_with_fake_podman(self):
        with tempfile.TemporaryDirectory() as td:
            bindir = Path(td)
            podman = bindir / "podman"
            podman.write_text(
                "#!/usr/bin/env bash\n"
                "set -e\n"
                "args=\"$*\"\n"
                "if [[ \"$args\" == *\"btool props list asteron:hec\"* ]]; then echo 'INDEXED_EXTRACTIONS = HEC'; exit 0; fi\n"
                "if [[ \"$args\" == *\"/opt/splunk/bin/splunk status\"* ]]; then echo 'splunkd is running'; exit 0; fi\n"
                "if [[ \"$args\" == *\"/opt/splunk/bin/splunk list index\"* ]]; then echo 'notable'; exit 0; fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            podman.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{bindir}:{env['PATH']}"
            env["SPLUNK_CONTAINER"] = "fake-splunk"

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


if __name__ == "__main__":
    unittest.main()
