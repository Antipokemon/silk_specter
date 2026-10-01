import csv
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AnswerFormatGuidanceTests(unittest.TestCase):
    def test_multi_value_questions_explain_input_format_and_stay_synchronized(self):
        with (ROOT / "instructor/questions/easy_questions.csv").open() as f:
            instructor = list(csv.DictReader(f))
        with (ROOT / "question_bank/easy/questions.csv").open() as f:
            bank = {r["ChallengeID"]: r["Question"] for r in csv.DictReader(f)}
        with (ROOT / "participant/scenarios/easy/ctf_questions.csv").open() as f:
            participant = {r["Number"]: r["Question"] for r in csv.DictReader(f)}

        checked = 0
        for row in instructor:
            answer_type = row.get("answer_type", "").strip()
            if answer_type not in {"set", "ordered_sequence"}:
                continue

            qid = row["question_id"]
            question = row["question"]
            checked += 1

            self.assertIn("Answer format example:", question, qid)
            self.assertIn("spaces around separators are optional", question, qid)

            if answer_type == "set":
                self.assertIn("value1;value2", question, qid)
                self.assertIn("order does not matter", question, qid)
            else:
                self.assertIn("value1>value2>value3", question, qid)
                self.assertIn("order matters", question, qid)

            self.assertEqual(bank[qid], question, qid)
            self.assertEqual(participant[qid], question, qid)

        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
