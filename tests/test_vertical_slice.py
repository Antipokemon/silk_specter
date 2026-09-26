import csv, ipaddress, json, re, unittest
from pathlib import Path
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[1]

class VerticalSliceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg=json.loads((ROOT/'config/scenarios/easy.json').read_text())
        cls.manifest=json.loads((ROOT/'dataset/easy/manifest.json').read_text())
        with (ROOT/'dataset/ground_truth_events.csv').open() as f: cls.truth=list(csv.DictReader(f))
        with (ROOT/'instructor/questions/easy_questions.csv').open() as f: cls.questions=list(csv.DictReader(f))
        with (ROOT/'instructor/questions/easy_hints.csv').open() as f: cls.hints=list(csv.DictReader(f))

    def test_20_sites(self):
        sites=json.loads((ROOT/'config/sites.json').read_text())['sites']
        self.assertEqual(len(sites),20)
        self.assertEqual(len({s['code'] for s in sites}),20)

    def test_campaign_bounds_utc(self):
        start=datetime.fromisoformat(self.cfg['start'].replace('Z','+00:00'))
        end=datetime.fromisoformat(self.cfg['end'].replace('Z','+00:00'))
        for r in self.truth:
            t=datetime.fromisoformat(r['time'].replace('Z','+00:00'))
            self.assertGreaterEqual(t,start)
            self.assertLessEqual(t,end)

    def test_participant_raw_has_no_ground_truth_labels(self):
        banned=['EASY-ACCESS','EASY-EXFIL','truth_label','attack_event','mitre_technique','question_tags','synthetic=true']
        for p in (ROOT/'dataset/easy/raw').glob('*.log'):
            data=p.read_text(errors='ignore')
            for term in banned:
                self.assertNotIn(term,data,p.name)

    def test_external_attribution_ranges(self):
        self.assertIn(ipaddress.ip_address(self.cfg['benign_scanner_ip']),ipaddress.ip_network('199.45.154.0/24'))
        self.assertIn(ipaddress.ip_address(self.cfg['actor_initial_ip']),ipaddress.ip_network('23.20.0.0/14'))
        self.assertIn(ipaddress.ip_address(self.cfg['actor_exfil_ip']),ipaddress.ip_network('50.19.0.0/16'))

    def test_core_sourcetypes(self):
        required={'XmlWinEventLog','syslog','linux_audit','linux_secure','bro:conn:json','bro:dns:json','bro:http:json','bro:ssl:json','bro:smb_files:json','bro:dce_rpc:json','aws:cloudtrail','aws:cloudwatchlogs:vpcflow','gitlab:audit','servicenow:audit','tenable:io:vuln','sccm:client','wsus:client','ivanti:events','vdi:session','mft:transfer','pan:traffic','fortigate_traffic','cisco:asa','cisco:ios','juniper','ms:defender:eventhub','trellix:epo','dlp:events','pacs:access'}
        self.assertTrue(required.issubset(set(self.manifest['sourcetypes'])))

    def test_sysmon_windows_and_linux_present(self):
        raws='\n'.join(p.read_text(errors='ignore') for p in (ROOT/'dataset/easy/raw').glob('*.log'))
        self.assertIn('Microsoft-Windows-Sysmon',raws)
        self.assertIn('Linux-Sysmon',raws)

    def test_network_device_layer_policy(self):
        cfg=json.loads((ROOT/'config/network_devices.json').read_text())
        for site in cfg['sites']:
            vendors=[x['vendor'] for x in site['firewall_layers']]
            self.assertEqual(len(vendors),len(set(vendors)))
            self.assertIn(len(vendors),(2,3))

    def test_detection_pack_isolation(self):
        for p in (ROOT/'splunk/detections/easy').glob('*.spl'):
            s=p.read_text().lower()
            self.assertIn('index=asteron_easy',s,p.name)
            self.assertNotIn('asteron_medium',s,p.name)
            self.assertNotIn('asteron_hard',s,p.name)

    def test_questions_unique_and_hinted(self):
        ids=[q['question_id'] for q in self.questions]
        self.assertEqual(len(ids),len(set(ids)))
        hint_counts={i:0 for i in ids}
        for h in self.hints: hint_counts[h['question_id']]+=1
        self.assertTrue(all(v>=2 for v in hint_counts.values()))
        self.assertEqual(len(self.questions),180)

    def test_first_questions_are_environment_familiarization(self):
        self.assertTrue(all(q['category']=='environment_familiarization' for q in self.questions[:15]))
        self.assertFalse(any(q['category']=='discovery' for q in self.questions[:15]))

    def test_attack_network_path_observable(self):
        activities={r['activity_id'] for r in self.truth if r['sourcetype'].startswith('bro:')}
        for a in ['EASY-ACCESS-001','EASY-GIT-001','EASY-WIN-PIVOT-001','EASY-XSPIVOT-001','EASY-EXFIL-001']:
            self.assertIn(a,activities)


    def test_eventrecordid_monotonic_by_channel(self):
        import collections
        pat_time=re.compile(r'<TimeCreated SystemTime="([^"]+)"')
        pat_id=re.compile(r'<EventRecordID>(\d+)</EventRecordID>')
        pat_chan=re.compile(r'<Channel>([^<]+)</Channel>')
        pat_comp=re.compile(r'<Computer>([^<]+)</Computer>')
        groups=collections.defaultdict(list)
        for p in (ROOT/'dataset/easy/raw').glob('*.log'):
            for line in p.read_text(errors='ignore').splitlines():
                mt,mi,mc,mh=pat_time.search(line),pat_id.search(line),pat_chan.search(line),pat_comp.search(line)
                if all((mt,mi,mc,mh)):
                    groups[(mh.group(1),mc.group(1))].append((mt.group(1),int(mi.group(1))))
        self.assertTrue(groups)
        for key,vals in groups.items():
            vals.sort(key=lambda x:x[0])
            ids=[x[1] for x in vals]
            self.assertEqual(ids,sorted(ids),key)
            self.assertEqual(len(ids),len(set(ids)),key)

    def test_hec_ingest_stream_count_and_metadata(self):
        p=ROOT/'dataset/easy/hec/events.jsonl'
        rows=[json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x.strip()]
        self.assertEqual(len(rows),self.manifest['events'])
        # Background volume is intentionally configurable. Reconcile the generated
        # stream against the generated validation metadata instead of a fixed total.
        with (ROOT/'dataset/easy/expected_counts.csv').open() as f:
            expected=sum(int(r['expected_count']) for r in csv.DictReader(f))
        self.assertEqual(len(rows),expected)
        self.assertTrue(all({'time','host','source','sourcetype','event'} <= set(r) for r in rows))
        self.assertFalse(any('truth_label' in r or 'activity_id' in r for r in rows))

    def test_hec_ingest_stream_time_bounds(self):
        p=ROOT/'dataset/easy/hec/events.jsonl'
        start=datetime.fromisoformat(self.cfg['start'].replace('Z','+00:00')).timestamp()
        end=datetime.fromisoformat(self.cfg['end'].replace('Z','+00:00')).timestamp()
        for line in p.read_text(encoding='utf-8').splitlines():
            r=json.loads(line)
            self.assertGreaterEqual(float(r['time']),start)
            self.assertLessEqual(float(r['time']),end)

    def test_corelight_zeek_sourcetype_metadata(self):
        expected={'bro:conn:json','bro:dns:json','bro:http:json','bro:ssl:json','bro:smb_files:json'}
        self.assertTrue(expected.issubset(set(self.manifest['sourcetypes'])))
        legacy={'zeek:conn','zeek:dns','zeek:http','zeek:tls','zeek:ssl','zeek:smb_files'}
        self.assertTrue(legacy.isdisjoint(set(self.manifest['sourcetypes'])))
        hec=[json.loads(x) for x in (ROOT/'dataset/easy/hec/events.jsonl').read_text().splitlines() if x.strip()]
        self.assertFalse(any(r.get('sourcetype') in legacy for r in hec))

    def test_expanded_easy_scale(self):
        # Keep minimum environment richness, but allow benign/noise volume to grow.
        self.assertGreaterEqual(self.manifest['events'],56844)
        self.assertGreaterEqual(self.manifest['hosts'],700)
        self.assertGreaterEqual(len(self.manifest['sourcetypes']),36)

    def test_expected_counts_reconcile(self):
        with (ROOT/'dataset/easy/expected_counts.csv').open() as f:
            rows=list(csv.DictReader(f))
        self.assertEqual(sum(int(r['expected_count']) for r in rows),self.manifest['events'])
        self.assertEqual({r['sourcetype'] for r in rows},set(self.manifest['sourcetypes']))

    def test_easy_campaign_has_full_lifecycle_activity(self):
        required={
            'EASY-RECON-ACTOR-001','EASY-ACCESS-001','EASY-EXECUTION-001','EASY-PERSIST-001',
            'EASY-PRIVESC-001','EASY-CREDACCESS-001','EASY-WIN-DISC-EXPANDED','EASY-LATERAL-001',
            'EASY-C2-001','EASY-COLLECT-EXPANDED','EASY-STAGE-001','EASY-EXFIL-001','EASY-CLEANUP-001'
        }
        activities={r['activity_id'] for r in self.truth if r['truth_label']=='malicious'}
        self.assertTrue(required.issubset(activities))
        malicious=[r for r in self.truth if r['truth_label']=='malicious']
        self.assertGreaterEqual(len(malicious),1000)
        stage=[r for r in self.truth if r['activity_id']=='EASY-STAGE-001']
        self.assertGreaterEqual(len(stage),40)
        ex=[r for r in self.truth if r['activity_id']=='EASY-EXFIL-001']
        self.assertGreaterEqual(len(ex),5)

if __name__=='__main__': unittest.main()
