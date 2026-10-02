import csv
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AnswerFormatGuidanceTests(unittest.TestCase):
    def test_multi_value_questions_explain_input_format(self):
        for track in ("easy", "medium", "hard"):
            with (ROOT / "question_bank" / track / "questions.csv").open(newline="", encoding="utf-8") as f:
                questions = list(csv.DictReader(f))
            with (ROOT / "question_bank" / track / "answers.csv").open(newline="", encoding="utf-8") as f:
                answers = {r["Number"]: r for r in csv.DictReader(f)}

            checked = 0
            for row in questions:
                answer_type = answers[row["Number"]].get("AnswerType", "").strip()
                if answer_type not in {"set", "ordered_sequence"}:
                    continue
                checked += 1
                question = row["Question"]
                self.assertIn("Answer format example:", question, row["ChallengeID"])
                self.assertIn("spaces", question.lower(), row["ChallengeID"])
                if answer_type == "set":
                    self.assertIn("value1;value2", question, row["ChallengeID"])
                else:
                    self.assertIn("value1>value2>value3", question, row["ChallengeID"])
            self.assertGreater(checked, 0, track)


if __name__ == "__main__":
    unittest.main()
