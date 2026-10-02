import csv, json, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class MediumStaticCampaignTests(unittest.TestCase):
    def test_static_campaign_exists_and_is_not_empty(self):
        p=ROOT/'scenario_data/medium/attack_events.jsonl'
        rows=[json.loads(x) for x in p.read_text().splitlines() if x.strip()]
        self.assertGreaterEqual(len(rows),60)
        self.assertTrue(all(r['scenario']=='medium' for r in rows))
        self.assertTrue(any(r['truth_label']=='malicious' for r in rows))
        self.assertTrue(any(r['truth_label']=='benign' for r in rows))

    def test_medium_question_answer_hint_coverage(self):
        with (ROOT/'question_bank/medium/questions.csv').open() as f:q=list(csv.DictReader(f))
        with (ROOT/'question_bank/medium/answers.csv').open() as f:a=list(csv.DictReader(f))
        with (ROOT/'question_bank/medium/hints.csv').open() as f:h=list(csv.DictReader(f))
        self.assertEqual(len(q),170)
        self.assertEqual(len(a),170)
        self.assertEqual(len(h),510)
        nums={r['Number'] for r in q}
        self.assertEqual(nums,{r['Number'] for r in a})
        self.assertEqual(nums,{r['Number'] for r in h})
        self.assertTrue(all(r['Subject'] for r in q))

    def test_medium_has_reduced_detection_pack(self):
        detections=list((ROOT/'splunk/detections/medium').glob('*.spl'))
        easy=list((ROOT/'splunk/detections/easy').glob('*.spl'))
        self.assertEqual(len(detections),8)
        self.assertLess(len(detections),len(easy))

if __name__=='__main__': unittest.main()
