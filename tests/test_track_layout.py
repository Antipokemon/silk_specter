import csv
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TrackLayoutTests(unittest.TestCase):
    def test_all_tracks_have_static_campaign_and_ingest_ready_baseline(self):
        for track in ("easy", "medium", "hard"):
            static = ROOT / "scenario_data" / track / "attack_events.jsonl"
            self.assertTrue(static.is_file(), track)
            self.assertGreater(static.stat().st_size, 0, track)

            base = ROOT / "dataset" / track
            self.assertTrue((base / "hec/events.jsonl").is_file(), track)
            self.assertTrue((base / "raw").is_dir(), track)
            self.assertTrue(any((base / "raw").glob("*.log")), track)
            self.assertTrue((base / "manifest.json").is_file(), track)
            self.assertTrue((base / "expected_counts.csv").is_file(), track)

    def test_notable_noise_increases_with_difficulty(self):
        manifests = {
            track: json.loads((ROOT / "dataset" / track / "notables/manifest.json").read_text())
            for track in ("easy", "medium", "hard")
        }
        self.assertLess(manifests["easy"]["noise_notables"], manifests["medium"]["noise_notables"])
        self.assertLess(manifests["medium"]["noise_notables"], manifests["hard"]["noise_notables"])
        self.assertEqual(manifests["easy"]["noise_notables"], 25)
        self.assertEqual(manifests["medium"]["noise_notables"], 60)
        self.assertEqual(manifests["hard"]["noise_notables"], 120)

    def test_participant_notables_do_not_leak_disposition_or_activity_id(self):
        for track in ("easy", "medium", "hard"):
            path = ROOT / "dataset" / track / "notables/hec/events.jsonl"
            for line in path.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                raw = row["event"]
                self.assertNotIn("expected_disposition", raw, track)
                self.assertNotIn("activity_id", raw, track)
                self.assertNotIn("truth_label", raw, track)

    def test_notable_ground_truth_reconciles(self):
        for track in ("easy", "medium", "hard"):
            manifest = json.loads((ROOT / "dataset" / track / "notables/manifest.json").read_text())
            with (ROOT / "instructor" / "findings" / f"{track}_notable_ground_truth.csv").open() as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), manifest["events"], track)


    def test_redundant_exports_are_not_committed(self):
        self.assertFalse((ROOT / "dataset/ground_truth").exists())
        self.assertFalse((ROOT / "dataset/ground_truth_events.csv").exists())
        self.assertFalse((ROOT / "release").exists())
        self.assertFalse((ROOT / "participant/environment/topology.svg").exists())
        self.assertTrue((ROOT / "docs/topology.svg").is_file())
        self.assertFalse((ROOT / "instructor/questions").exists())
        self.assertFalse((ROOT / "instructor/ground_truth/medium_events.csv").exists())
        self.assertFalse((ROOT / "instructor/ground_truth/hard_events.csv").exists())

    def test_changelog_is_consolidated(self):
        self.assertTrue((ROOT / "CHANGELOG.md").is_file())
        self.assertFalse(list(ROOT.glob("CHANGELOG-v*.md")))


if __name__ == "__main__":
    unittest.main()
