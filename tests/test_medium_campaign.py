import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'generator'))

from core.scenario import load_scenario, parse_utc
from core.state import EventStore
from scenarios.medium import build_campaign


class MediumCampaignTests(unittest.TestCase):
    def test_medium_campaign_builds_distinct_multiregion_evidence(self):
        ctx = load_scenario(ROOT, 'medium')
        store = EventStore('medium')
        result = build_campaign(store, ctx, {'config': ctx.config, 'sites': []})

        self.assertEqual(result['campaign'], 'medium')
        self.assertGreaterEqual(len(store.events), 50)
        self.assertTrue(all(e.scenario == 'medium' for e in store.events))
        self.assertTrue(all(ctx.start <= parse_utc(e.time) <= ctx.end for e in store.events))

        activities = {e.activity_id for e in store.events}
        for required in {
            'MED-ACCESS-001', 'MED-CRED-001', 'MED-LATERAL-001',
            'MED-CLOUD-002', 'MED-COLLECT-001', 'MED-STAGE-002',
            'MED-EXFIL-001', 'MED-CLEANUP-001'
        }:
            self.assertIn(required, activities)

        sourcetypes = {e.sourcetype for e in store.events}
        for required in {
            'XmlWinEventLog', 'bro:conn:json', 'aws:cloudtrail',
            'linux_audit', 'pan:traffic', 'fortigate_traffic',
            'ms:defender:eventhub', 'dlp:events'
        }:
            self.assertIn(required, sourcetypes)

        malicious_hosts = {e.host for e in store.events if e.truth_label == 'malicious'}
        self.assertTrue({'UKLO-JMP-01', 'DEFR-ENG-APP-03', 'NLAM-OPS-LNX-04', 'AUSY-ENG-APP-04'} <= malicious_hosts)

    def test_medium_remains_authoring_until_runtime_validation(self):
        ctx = load_scenario(ROOT, 'medium')
        self.assertEqual(ctx.status, 'authoring')


if __name__ == '__main__':
    unittest.main()
