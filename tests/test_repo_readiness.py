import csv, json, unittest
from datetime import timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class RepoReadinessTests(unittest.TestCase):
    def test_scenario_registry_and_quality_gates(self):
        expected={'easy':'validated','medium':'authoring','hard':'authoring'}
        for slug,status in expected.items():
            p=ROOT/'config'/'scenarios'/f'{slug}.json'
            self.assertTrue(p.exists(),slug)
            cfg=json.loads(p.read_text())
            self.assertEqual(cfg['status'],status)
            self.assertIn('start',cfg); self.assertIn('end',cfg); self.assertIn('index',cfg)

    def test_question_pool_artifacts_exist(self):
        for slug in ['easy','medium','hard']:
            for fn in ['questions.csv','answers.csv','hints.csv','STATUS.md']:
                self.assertTrue((ROOT/'question_bank'/slug/fn).exists(),f'{slug}/{fn}')

    def test_easy_question_pool_has_answer_and_hint_coverage(self):
        with (ROOT/'question_bank/easy/questions.csv').open() as f: qs=list(csv.DictReader(f))
        with (ROOT/'question_bank/easy/answers.csv').open() as f: ans=list(csv.DictReader(f))
        with (ROOT/'question_bank/easy/hints.csv').open() as f: hints=list(csv.DictReader(f))
        qids={q['question_id'] for q in qs}
        self.assertEqual(qids,{a['question_id'] for a in ans})
        hinted={h['question_id'] for h in hints}
        self.assertTrue(qids <= hinted)

    def test_scenario_context_relative_window(self):
        from generator.core.scenario import load_scenario
        ctx=load_scenario(ROOT,'easy','2026-05-04T00:00:00Z','2026-05-08T23:59:59Z')
        dt=ctx.at(4,19,20)
        self.assertEqual(dt.tzinfo,timezone.utc)
        self.assertEqual(dt.isoformat(),'2026-05-08T19:20:00+00:00')

    def test_network_flow_validation(self):
        from generator.core.network import NetworkFlow, NetworkLedger
        from datetime import datetime
        f=NetworkFlow('test',datetime(2026,4,6,tzinfo=timezone.utc),'10.44.30.37',50000,'10.47.60.21',5985,'tcp',100,200,1.2)
        l=NetworkLedger(); l.add_flow(f); l.observe('test','zeek'); l.observe('test','firewall'); l.require_observations('test',{'zeek','firewall'})

    def test_required_repo_docs_exist(self):
        for fn in ['AGENTS.md','README.md','docs/GENERATE_AND_LOAD.md','docs/SPLUNK_LOAD.md','docs/NETWORK_PURPOSE_AND_LAYOUT.md','docs/TA_COMPATIBILITY.md','docs/SCENARIO_AUTHORING.md','docs/QUESTION_BANK.md']:
            self.assertTrue((ROOT/fn).exists(),fn)

if __name__=='__main__': unittest.main()
