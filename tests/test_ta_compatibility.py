import json
import re
import unittest
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HEC=ROOT/'dataset/easy/hec/events.jsonl'


class TACompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text=HEC.read_text(encoding='utf-8')
        if text.startswith('version https://git-lfs.github.com/spec/v1'):
            raise unittest.SkipTest('Easy LFS dataset is not materialized; run git lfs pull or make generate-easy')
        cls.events=[json.loads(line) for line in text.splitlines() if line.strip()]
        cls.by={}
        for e in cls.events:
            cls.by.setdefault(e['sourcetype'],[]).append(e)

    def test_cisco_asa_302013_has_numeric_unique_connection_id(self):
        rows=[e['event'] for e in self.by.get('cisco:asa',[]) if '%ASA-6-302013:' in e['event']]
        self.assertGreater(len(rows),100)
        ids=[]
        pat=re.compile(r'%ASA-6-302013:\s+Built (?:inbound|outbound) TCP connection (\d+) for ')
        for row in rows:
            m=pat.search(row)
            self.assertIsNotNone(m,row)
            ids.append(m.group(1))
        self.assertEqual(len(ids),len(set(ids)))

    def test_cisco_ios_auth_and_config_coverage(self):
        blob='\n'.join(e['event'] for e in self.by.get('cisco:ios',[]))
        self.assertIn('%SEC_LOGIN-5-LOGIN_SUCCESS:',blob)
        self.assertIn('%SEC_LOGIN-4-LOGIN_FAILED:',blob)
        self.assertRegex(blob,r'%SYS-\d+-CONFIG_I:')
        self.assertIn('%OSPF-',blob)

    def test_cloudtrail_sources_and_parameters(self):
        mapping={
            'AssumeRole':'sts.amazonaws.com','GetCallerIdentity':'sts.amazonaws.com',
            'DescribeInstances':'ec2.amazonaws.com','DescribeSecurityGroups':'ec2.amazonaws.com',
            'DescribeSubnets':'ec2.amazonaws.com','DescribeVpcs':'ec2.amazonaws.com',
            'ListBuckets':'s3.amazonaws.com','GetObject':'s3.amazonaws.com','ListObjectsV2':'s3.amazonaws.com',
            'DescribeLogGroups':'logs.amazonaws.com','GetSecretValue':'secretsmanager.amazonaws.com','ListSecrets':'secretsmanager.amazonaws.com',
            'GetParameter':'ssm.amazonaws.com','DescribeDBInstances':'rds.amazonaws.com',
            'DescribeLoadBalancers':'elasticloadbalancing.amazonaws.com','DescribeRepositories':'ecr.amazonaws.com',
            'ListFunctions':'lambda.amazonaws.com','ListDistributions':'cloudfront.amazonaws.com',
            'GetAccountAuthorizationDetails':'iam.amazonaws.com','ListRoles':'iam.amazonaws.com','ListUsers':'iam.amazonaws.com',
        }
        seen=set()
        for e in self.by.get('aws:cloudtrail',[]):
            x=json.loads(e['event']); name=x['eventName']
            if name in mapping:
                seen.add(name)
                self.assertEqual(x['eventSource'],mapping[name],name)
                self.assertNotIn('resource',x.get('requestParameters') or {})
                self.assertNotIn('syntheticContext',x.get('requestParameters') or {})
                self.assertEqual(x['recipientAccountId'],x['userIdentity']['accountId'])
        for required in ['GetObject','GetSecretValue','AssumeRole','DescribeDBInstances','DescribeLoadBalancers','DescribeRepositories','GetParameter','ListFunctions','ListDistributions']:
            self.assertIn(required,seen)
        samples={}
        for e in self.by.get('aws:cloudtrail',[]):
            x=json.loads(e['event']); samples.setdefault(x['eventName'],x)
        self.assertTrue({'bucketName','key'} <= set(samples['GetObject']['requestParameters']))
        self.assertIn('secretId',samples['GetSecretValue']['requestParameters'])
        self.assertTrue({'roleArn','roleSessionName'} <= set(samples['AssumeRole']['requestParameters']))
        self.assertIn('dBInstanceIdentifier',samples['DescribeDBInstances']['requestParameters'])
        self.assertIn('loadBalancerArns',samples['DescribeLoadBalancers']['requestParameters'])
        self.assertIn('repositoryNames',samples['DescribeRepositories']['requestParameters'])
        self.assertIn('name',samples['GetParameter']['requestParameters'])

    def test_defender_eventhub_layout_and_detection_categories(self):
        self.assertNotIn('ms:defender:endpoint',self.by)
        rows=self.by.get('ms:defender:eventhub',[])
        self.assertGreater(len(rows),100)
        cats=Counter()
        for e in rows:
            x=json.loads(e['event'])
            self.assertIn('category',x)
            self.assertIsInstance(x.get('properties'),dict)
            cats[x['category']]+=1
        self.assertGreater(cats['AdvancedHunting-DeviceEvents'],100)
        self.assertGreater(cats['AdvancedHunting-AlertInfo'],100)
        self.assertGreater(cats['AdvancedHunting-AlertEvidence'],100)

        info=next(json.loads(e['event'])['properties'] for e in rows if json.loads(e['event'])['category']=='AdvancedHunting-AlertInfo')
        self.assertTrue({'Timestamp','AlertId','Title','Category','Severity','ServiceSource','DetectionSource'} <= set(info))
        evidence=next(json.loads(e['event'])['properties'] for e in rows if json.loads(e['event'])['category']=='AdvancedHunting-AlertEvidence')
        self.assertTrue({'Timestamp','AlertId','DeviceName','FileName','ThreatFamily','AccountName','AdditionalFields','Severity'} <= set(evidence))
        additional=json.loads(evidence['AdditionalFields'])
        self.assertTrue({'ThreatName','RemediationStatus','RemediationAction'} <= set(additional))

    def test_fortigate_supported_sourcetype(self):
        self.assertIn('fortigate_traffic',self.by)
        self.assertNotIn('fortigate:traffic',self.by)
        self.assertIn('type="traffic"',self.by['fortigate_traffic'][0]['event'])

    def test_ivanti_patch_update_shape(self):
        rows=self.by.get('ivanti:events',[])
        self.assertGreater(len(rows),10)
        for e in rows[:50]:
            x=json.loads(e['event'])
            self.assertIn(x['action'],{'patch_install','update_deploy','package_install','software_distribution'})
            self.assertTrue({'target_device','update_id','package_name','package_version','file_name','status'} <= set(x))
            self.assertIn(x['status'],{'success','failed'})

    def test_juniper_auth_success_failure_and_rpd_separation(self):
        auth=self.by.get('juniper',[])
        self.assertGreater(len(auth),20)
        successes=[e for e in auth if 'UI_LOGIN_EVENT' in e['event']]
        failures=[e for e in auth if 'SSHD_LOGIN_FAILED' in e['event']]
        self.assertGreater(len(successes),len(failures))
        self.assertGreater(len(failures),5)
        for e in failures[:20]:
            self.assertIn('username=',e['event'])
            self.assertIn('source-address=',e['event'])
            self.assertIn('destination-address=',e['event'])
            self.assertIn('ssh-connection=',e['event'])
        self.assertFalse(any('RPD_BGP_NEIGHBOR_STATE_CHANGED' in e['event'] for e in auth))
        rpd=self.by.get('juniper:junos:firewall',[])
        self.assertGreater(len(rpd),10)
        self.assertTrue(any('RPD_BGP_NEIGHBOR_STATE_CHANGED' in e['event'] for e in rpd))

    def test_tacacs_has_pass_and_failure_outcomes(self):
        rows=self.by.get('tacacs',[])
        self.assertGreater(len(rows),20)
        results=Counter()
        for e in rows:
            m=re.search(r'\bresult=(PASS|FAIL|REJECT)\b',e['event'])
            self.assertIsNotNone(m,e['event'])
            results[m.group(1)]+=1
            for fld in ['server=','user=','device=','src=','service=','result=']:
                self.assertIn(fld,e['event'])
        self.assertGreater(results['PASS'],results['FAIL']+results['REJECT'])
        self.assertGreater(results['FAIL']+results['REJECT'],0)

    def test_wsus_status_diversity(self):
        rows=self.by.get('wsus:client',[])
        self.assertGreater(len(rows),50)
        statuses=Counter()
        for e in rows:
            x=json.loads(e['event'])
            self.assertTrue({'device','server','status','timestamp','title','update_id'} <= set(x))
            self.assertRegex(x['update_id'],r'^KB\d+$')
            self.assertIn('KB',x['title'])
            statuses[x['status']]+=1
        for required in ['Installed','Failed','Downloaded','Pending','RebootRequired']:
            self.assertGreater(statuses[required],0)
        self.assertGreater(statuses['Installed'],sum(v for k,v in statuses.items() if k!='Installed'))

    def test_linux_audit_model_relevant_types(self):
        blob='\n'.join(e['event'] for e in self.by.get('linux_audit',[]))
        for typ in ['SYSCALL','EXECVE','PROCTITLE','USER_AUTH','USER_LOGIN','USER_ACCT','CRED_ACQ']:
            self.assertIn(f'type={typ}',blob)
        self.assertRegex(blob,r'type=(ADD_USER|DEL_USER|USER_MGMT)')
        self.assertRegex(blob,r'type=(ADD_GROUP|GRP_MGMT)')
        self.assertRegex(blob,r'type=(USER_CHAUTHTOK|CRED_REFR)')

    def test_pan_traffic_exact_transform_width(self):
        rows=self.by.get('pan:traffic',[])
        self.assertGreater(len(rows),10)
        for e in rows[:100]:
            fields=e['event'].split(',')
            self.assertEqual(len(fields),61,e['event'])
            self.assertEqual(fields[3],'TRAFFIC')
            self.assertEqual(fields[4],'end')
            self.assertRegex(fields[22],r'^\d+$')
            self.assertIn(fields[30],{'allow','deny','drop','reset-client','reset-server','reset-both'})

    def test_windows_generic_sourcetype_and_channel_sources(self):
        self.assertIn('XmlWinEventLog',self.by)
        self.assertNotIn('XmlWinEventLog:Security',self.by)
        self.assertNotIn('XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',self.by)
        sources=Counter(e['source'] for e in self.by['XmlWinEventLog'])
        self.assertGreater(sources['XmlWinEventLog:Security'],100)
        self.assertGreater(sources['XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'],100)

    def test_windows_eventdata_name_attributes_are_single_quoted(self):
        rows=self.by.get('XmlWinEventLog',[])
        self.assertGreater(len(rows),100)
        for e in rows:
            if '<EventData>' in e['event']:
                self.assertNotIn('<Data Name="',e['event'])
                self.assertIn("<Data Name='",e['event'])

    def test_windows_security_change_event_coverage_and_fields(self):
        rows=[e for e in self.by.get('XmlWinEventLog',[]) if e['source']=='XmlWinEventLog:Security']
        by_id={eid:[] for eid in [4720,4726,4738,4728,4729,4732,4733]}
        for e in rows:
            for eid in by_id:
                if f'<EventID>{eid}</EventID>' in e['event']:
                    by_id[eid].append(e['event'])
        for eid,events in by_id.items():
            self.assertGreater(len(events),0,eid)
            sample=events[0]
            self.assertIn("<Data Name='SubjectUserName'>",sample)
            self.assertIn("<Data Name='TargetUserName'>",sample)
        for eid in [4728,4729,4732,4733]:
            self.assertIn("<Data Name='MemberName'>",by_id[eid][0])
            self.assertIn("<Data Name='MemberId'>",by_id[eid][0])

    def test_sysmon_event_ids_and_core_fields(self):
        rows=[e for e in self.by.get('XmlWinEventLog',[]) if e['source']=='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational']
        required={
            1:['Image','CommandLine','ProcessId','ParentProcessId','ParentImage','User','ProcessGuid','ParentProcessGuid'],
            3:['Image','ProcessId','User','SourceIp','SourcePort','DestinationIp','DestinationPort','Protocol','Initiated'],
            11:['Image','ProcessId','TargetFilename','CreationUtcTime'],
            22:['Image','ProcessId','QueryName','QueryStatus','QueryResults'],
        }
        for eid,fields in required.items():
            matches=[e['event'] for e in rows if f'<EventID>{eid}</EventID>' in e['event']]
            self.assertGreater(len(matches),0,eid)
            sample=matches[0]
            for fld in fields:
                self.assertIn(f"<Data Name='{fld}'>",sample,(eid,fld))

    def test_tenable_schema(self):
        rows=self.by.get('tenable:io:vuln',[])
        self.assertGreater(len(rows),10)
        for e in rows[:50]:
            x=json.loads(e['event'])
            self.assertTrue({'ipv4','ip','asset_fqdn','plugin','port'} <= set(x))
            self.assertTrue({'id','name','family','synopsis','cve','cvss3_base_score','risk_factor'} <= set(x['plugin']))
            self.assertTrue({'port','protocol'} <= set(x['port']))

    def test_x509_fingerprints_are_hash_formatted(self):
        rows=self.by.get('bro:x509:json',[])
        self.assertGreater(len(rows),0)
        for e in rows:
            x=json.loads(e['event'])
            self.assertRegex(x['fingerprint'],r'^(?:[A-F0-9]{40}|[A-F0-9]{64})$')
            self.assertTrue({'certificate.subject','certificate.issuer','certificate.serial','certificate.not_valid_before','certificate.not_valid_after','certificate.key_alg','certificate.sig_alg','san.dns'} <= set(x))


if __name__=='__main__':
    unittest.main()
