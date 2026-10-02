import csv
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {"easy": (180, 360), "medium": (170, 510), "hard": (150, 450)}


class CanonicalQuestionBankTests(unittest.TestCase):
    def test_question_bank_is_single_committed_source(self):
        self.assertFalse((ROOT / "instructor/questions").exists())
        for track in EXPECTED:
            self.assertFalse((ROOT / "participant/scenarios" / track / "ctf_questions.csv").exists())
            self.assertFalse((ROOT / "participant/scenarios" / track / "ctf_hints.csv").exists())

    def test_question_bank_contains_runtime_and_instructor_metadata(self):
        required_q = {
            "ctf_id", "Number", "Question", "StartTime", "EndTime", "BasePoints",
            "AdditionalBonusPoints", "AdditionalBonusInstructions", "Subject", "ChallengeID",
            "PrimarySourcetype", "LearningObjective", "ReferenceSPL",
        }
        required_a = {"ctf_id", "Number", "Answer", "AnswerType"}
        for track, (q_count, h_count) in EXPECTED.items():
            with (ROOT / "question_bank" / track / "questions.csv").open(newline="", encoding="utf-8") as f:
                q = list(csv.DictReader(f)); q_fields = set(q[0])
            with (ROOT / "question_bank" / track / "answers.csv").open(newline="", encoding="utf-8") as f:
                a = list(csv.DictReader(f)); a_fields = set(a[0])
            with (ROOT / "question_bank" / track / "hints.csv").open(newline="", encoding="utf-8") as f:
                h = list(csv.DictReader(f))
            self.assertEqual(len(q), q_count, track)
            self.assertEqual(len(a), q_count, track)
            self.assertEqual(len(h), h_count, track)
            self.assertTrue(required_q <= q_fields, track)
            self.assertTrue(required_a <= a_fields, track)
            self.assertEqual({x["Number"] for x in q}, {x["Number"] for x in a}, track)
            self.assertEqual({x["Number"] for x in q}, {x["Number"] for x in h}, track)
            self.assertTrue(all(x["ReferenceSPL"].strip() for x in q), track)
            self.assertTrue(all(x["AnswerType"].strip() for x in a), track)

    def test_medium_m014_source_answer_is_consistent_with_static_data(self):
        with (ROOT / "question_bank/medium/questions.csv").open(newline="", encoding="utf-8") as f:
            questions = {r["ChallengeID"]: r for r in csv.DictReader(f)}
        with (ROOT / "question_bank/medium/answers.csv").open(newline="", encoding="utf-8") as f:
            answers = {r["Number"]: r for r in csv.DictReader(f)}
        row = questions["M014"]
        self.assertEqual(answers[row["Number"]]["Answer"], "radius;XmlWinEventLog:Security")


if __name__ == "__main__":
    unittest.main()
