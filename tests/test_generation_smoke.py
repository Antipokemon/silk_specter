import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GenerationSmokeTests(unittest.TestCase):
    def test_small_generation_succeeds_for_all_tracks(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            for track in ("easy", "medium", "hard"):
                out = base / track
                cmd = [
                    "python3", str(ROOT / "generator/generate.py"),
                    "--scenario", track,
                    "--output", str(out),
                    "--background-events", "5",
                    "--enterprise-background-events", "20",
                ]
                if track != "easy":
                    cmd.append("--allow-authoring")
                subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                manifest = json.loads((out / "manifest.json").read_text())
                notables = json.loads((out / "notables/manifest.json").read_text())
                self.assertGreater(manifest["events"], 0, track)
                self.assertGreater(notables["events"], 0, track)
                self.assertTrue((out / "hec/events.jsonl").is_file(), track)
                self.assertTrue(any((out / "raw").glob("*.log")), track)
                self.assertFalse((base / "ground_truth").exists())


if __name__ == "__main__":
    unittest.main()
