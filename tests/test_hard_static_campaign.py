import csv, json, unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'generator'))
from core.scenario import load_scenario, parse_utc
from core.state import EventStore
from scenarios.hard import build_campaign

class HardStaticCampaignTests(unittest.TestCase):
    def test_static_campaign_loads_and_is_in_window(self):
        ctx=load_scenario(ROOT,'hard'); store=EventStore('hard')
        result=build_campaign(store,ctx,{'config':ctx.config,'sites':[]})
        self.assertEqual(result['campaign'],'hard')
        self.assertGreaterEqual(len(store.events),60)
        self.assertTrue(all(e.scenario=='hard' for e in store.events))
        self.assertTrue(all(ctx.start <= parse_utc(e.time) <= ctx.end for e in store.events))
        activities={e.activity_id for e in store.events}
        for required in {'HARD-ACCESS-001','HARD-PROXY-001','HARD-LATERAL-001','HARD-OT-PREP-001','HARD-COLLECT-001','HARD-STAGE-002','HARD-EXFIL-001','HARD-CLEANUP-001'}:
            self.assertIn(required,activities)
        st={e.sourcetype for e in store.events}
        for required in {'XmlWinEventLog','radius:auth','pan:traffic','bro:conn:json','bro:smb_files:json','linux_secure','linux_audit','syslog','mft:transfer','dlp:events','servicenow:audit'}:
            self.assertIn(required,st)
    def test_hard_question_bank_complete(self):
        with (ROOT/'question_bank/hard/questions.csv').open() as f: q=list(csv.DictReader(f))
        with (ROOT/'question_bank/hard/answers.csv').open() as f: a=list(csv.DictReader(f))
        with (ROOT/'question_bank/hard/hints.csv').open() as f: h=list(csv.DictReader(f))
        self.assertEqual(len(q),150); self.assertEqual(len(a),150); self.assertEqual(len(h),450)
        self.assertEqual({x['Number'] for x in q},{x['Number'] for x in a})
        counts={}
        for row in h: counts[row['Number']]=counts.get(row['Number'],0)+1
        self.assertTrue(all(counts.get(x['Number'])==3 for x in q))
        self.assertTrue(all(x['Subject'].strip() for x in q))

    def test_hard_hints_and_reference_pivots_are_track_specific(self):
        with (ROOT/'question_bank/hard/questions.csv').open() as f:
            questions=list(csv.DictReader(f))
        with (ROOT/'question_bank/hard/hints.csv').open() as f:
            hints=list(csv.DictReader(f))

        self.assertGreaterEqual(len({row['Hint'] for row in hints}), 40)
        old_generic={
            'Start from the evidence family named in the question and constrain the time window.',
            'Correlate identity, host, and network context rather than treating a single IOC as decisive.',
            'Use the instructor reference fields implied by the question and inspect the exact matching records.',
        }
        self.assertFalse(old_generic & {row['Hint'] for row in hints})
        self.assertTrue(all(row['ReferenceSPL'].strip() for row in questions))
        self.assertTrue(any('index=notable' in row['ReferenceSPL'] for row in questions if row['Subject']=='notable_triage'))

    def test_hard_remains_authoring(self):
        self.assertEqual(load_scenario(ROOT,'hard').status,'authoring')

if __name__=='__main__': unittest.main()
