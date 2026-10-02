#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
import argparse, json, random, uuid, sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
sys.path.insert(0,str(HERE))
from core.state import EventStore
from core.scenario import load_scenario, ScenarioContext, parse_utc
from renderers import windows, linux, zeek, network_devices, apps
from background import add_enterprise_background, add_defender_detection_background
from corroboration import add_attack_corroboration
from attack_expansion import add_attack_expansion
from scenarios.medium import build_campaign as build_medium_campaign
from scenarios.hard import build_campaign as build_hard_campaign

DEFAULT_BACKGROUND_EVENTS = 5000
DEFAULT_ENTERPRISE_BACKGROUND_EVENTS = 45000

CFG=json.loads((ROOT/'config/scenarios/easy.json').read_text())
CTX=ScenarioContext.from_dict('easy', CFG)
SITES=json.loads((ROOT/'config/sites.json').read_text())['sites']
SITE_BY_CODE={s['code']:s for s in SITES}

def iso(dt): return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
def epoch(dt): return dt.timestamp()
def zts(dt): return dt.timestamp()
def syslog_stamp(dt): return dt.astimezone(timezone.utc).strftime('%b %d %H:%M:%S')
def uuidg(name): return '{'+str(uuid.uuid5(uuid.NAMESPACE_DNS,'asteron:'+name))+'}'
def zuid(name): return 'C'+uuid.uuid5(uuid.NAMESPACE_DNS,'zeek:'+name).hex[:17]
def at(day,hour=0,minute=0,second=0,microsecond=0): return CTX.at(day,hour,minute,second,microsecond)

def resolve_generation_counts(cfg, background_override=None, enterprise_background_override=None):
    generation = cfg.get('generation', {})
    background = generation.get('background_events', DEFAULT_BACKGROUND_EVENTS) if background_override is None else background_override
    enterprise = generation.get('enterprise_background_events', DEFAULT_ENTERPRISE_BACKGROUND_EVENTS) if enterprise_background_override is None else enterprise_background_override
    background = int(background)
    enterprise = int(enterprise)
    if background < 0 or enterprise < 0:
        raise ValueError('Generation event counts must be non-negative integers')
    return background, enterprise

def add_attack(store):
    H=CFG['hosts']; pub=CFG['public_vip']; scanner=CFG['benign_scanner_ip']; actor=CFG['actor_initial_ip']; exfil=CFG['actor_exfil_ip']
    web=H['USHQ-WEB-02']; app=H['USHQ-APP-07']; dc=H['USHQ-DC-02']; dns=H['USHQ-DNS-01']; eng=H['USVA-ENG-APP-01']; fs=H['USVA-FS-01']
    us_hq_sensor='USHQ-ZEEK-01'; us_va_sensor='USVA-ZEEK-01'
    # 1. benign Censys exposure indexing
    t=at(0,13,4,17); uid=zuid('censys-scan')
    store.add(key='censys.conn',activity_id='EASY-RECON-BENIGN-001',time=iso(t),host=us_hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(t),uid,scanner,52344,web,443,service='ssl',orig_bytes=218,resp_bytes=1417,local_orig=False,local_resp=True),truth_label='benign',question_tags='external_recon,osint')
    store.add(key='censys.tls',activity_id='EASY-RECON-BENIGN-001',time=iso(t+timedelta(milliseconds=12)),host=us_hq_sensor,source='zeek:ssl',sourcetype='zeek:ssl',raw=zeek.tls(zts(t+.012*timedelta(seconds=1)),uid,scanner,52344,web,443,'portal.asteron.example','t13d1516h2_8daaf6152771_02713d6af862'),truth_label='benign',question_tags='external_recon,osint')
    store.add(key='censys.http',activity_id='EASY-RECON-BENIGN-001',time=iso(t+timedelta(milliseconds=80)),host=us_hq_sensor,source='zeek:http',sourcetype='zeek:http',raw=zeek.http(zts(t+timedelta(milliseconds=80)),uid,scanner,52344,web,443,'GET','portal.asteron.example','/',200,'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)'),truth_label='benign',question_tags='external_recon,osint')
    store.add(key='censys.pan',activity_id='EASY-RECON-BENIGN-001',time=iso(t),host='USHQ-FW-01',source='pan:traffic',sourcetype='pan:traffic',raw=network_devices.palo_alto(t.strftime('%Y/%m/%d %H:%M:%S'),'PA-USHQ-001',scanner,pub,52344,443,'allow','PUBLIC-WEB','untrust','dmz',bytes_out=218,bytes_in=1417,nat_dst=web),truth_label='benign',question_tags='external_recon,osint')
    store.add(key='censys.waf',activity_id='EASY-RECON-BENIGN-001',time=iso(t),host='AWS-WEB-WAF-01',source='aws:waf',sourcetype='aws:waf',raw=apps.waf(iso(t),scanner,'portal.asteron.example','/',200,'ALLOW','PublicPortalDefault','req-censys-001'),truth_label='benign',question_tags='external_recon,osint')

    # 2. actor probes + web exploitation evidence, but no exploit payload
    t=at(0,15,22,41); uid=zuid('actor-web-1')
    store.add(key='actor.web.conn',activity_id='EASY-ACCESS-001',time=iso(t),host=us_hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(t),uid,actor,48722,web,443,service='ssl',duration=2.41,orig_bytes=5841,resp_bytes=2764,local_orig=False,local_resp=True),truth_label='malicious',technique='T1190',question_tags='initial_access')
    store.add(key='actor.web.tls',activity_id='EASY-ACCESS-001',time=iso(t+timedelta(milliseconds=15)),host=us_hq_sensor,source='zeek:ssl',sourcetype='zeek:ssl',raw=zeek.tls(zts(t+timedelta(milliseconds=15)),uid,actor,48722,web,443,'portal.asteron.example','t13d1517h2_8daaf6152771_02713d6af862'),truth_label='malicious',technique='T1190',question_tags='initial_access')
    store.add(key='actor.web.http1',activity_id='EASY-ACCESS-001',time=iso(t+timedelta(milliseconds=200)),host=us_hq_sensor,source='zeek:http',sourcetype='zeek:http',raw=zeek.http(zts(t+timedelta(milliseconds=200)),uid,actor,48722,web,443,'POST','portal.asteron.example','/api/render',500,'Mozilla/5.0',resp_len=188),truth_label='malicious',technique='T1190',question_tags='initial_access')
    store.add(key='actor.web.http2',activity_id='EASY-ACCESS-001',time=iso(t+timedelta(seconds=11)),host=us_hq_sensor,source='zeek:http',sourcetype='zeek:http',raw=zeek.http(zts(t+timedelta(seconds=11)),uid,actor,48722,web,443,'GET','portal.asteron.example','/assets/.runtime/status',200,'Mozilla/5.0',resp_len=92),truth_label='malicious',technique='T1505.003',question_tags='initial_access,webshell')
    store.add(key='actor.web.waf1',activity_id='EASY-ACCESS-001',time=iso(t),host='AWS-WEB-WAF-01',source='aws:waf',sourcetype='aws:waf',raw=apps.waf(iso(t),actor,'portal.asteron.example','/api/render',500,'COUNT','AppInputAnomaly','req-actor-001'),truth_label='malicious',technique='T1190',question_tags='initial_access')
    store.add(key='actor.web.waf2',activity_id='EASY-ACCESS-001',time=iso(t+timedelta(seconds=11)),host='AWS-WEB-WAF-01',source='aws:waf',sourcetype='aws:waf',raw=apps.waf(iso(t+timedelta(seconds=11)),actor,'portal.asteron.example','/assets/.runtime/status',200,'ALLOW','PublicPortalDefault','req-actor-002'),truth_label='malicious',technique='T1505.003',question_tags='initial_access')
    store.add(key='actor.web.pan',activity_id='EASY-ACCESS-001',time=iso(t),host='USHQ-FW-01',source='pan:traffic',sourcetype='pan:traffic',raw=network_devices.palo_alto(t.strftime('%Y/%m/%d %H:%M:%S'),'PA-USHQ-001',actor,pub,48722,443,'allow','PUBLIC-WEB','untrust','dmz',bytes_out=5841,bytes_in=2764,nat_dst=web),truth_label='malicious',technique='T1190',question_tags='initial_access')

    # 3. file create and Linux shell/discovery
    t2=t+timedelta(seconds=18); pg=uuidg('linux-shell'); pid=18422
    store.add(key='linux.file.webshell',activity_id='EASY-ACCESS-001',time=iso(t2),host='USHQ-WEB-02',source='/var/log/syslog',sourcetype='syslog',raw=linux.linux_sysmon_file(syslog_time=syslog_stamp(t2),iso_time=iso(t2),record_id=store.record_id_at('USHQ-WEB-02','Linux-Sysmon/Operational',t2),host='USHQ-WEB-02',guid=pg,pid=pid,image='/usr/bin/java',target='/srv/asteron-web/assets/.runtime/status',user='asteronweb'),truth_label='malicious',technique='T1505.003',question_tags='webshell,file_create')
    commands=[('id','T1033'),('uname -a','T1082'),('ip addr','T1016'),('ip route','T1016'),('ss -plant','T1049'),('ps -ef','T1057'),('cat /etc/resolv.conf','T1016')]
    for i,(cmd,tech) in enumerate(commands):
        et=t2+timedelta(seconds=15+i*7); thispid=pid+i+1; g=uuidg('linux-'+cmd)
        raw=linux.linux_sysmon_process(syslog_time=syslog_stamp(et),iso_time=iso(et),record_id=store.record_id_at('USHQ-WEB-02','Linux-Sysmon/Operational',et),host='USHQ-WEB-02',guid=g,pid=thispid,ppid=pid,image='/bin/sh',cmd='/bin/sh -c '+cmd,user='www-data')
        store.add(key='linux.proc.'+str(i),activity_id='EASY-DISCOVERY-001',time=iso(et),host='USHQ-WEB-02',source='/var/log/syslog',sourcetype='syslog',raw=raw,truth_label='malicious',technique=tech,question_tags='linux_discovery')
        for j,line in enumerate(linux.audit_exec(epoch=int(et.timestamp()),serial=400+i,host='USHQ-WEB-02',pid=thispid,ppid=pid,uid=33,exe='/bin/sh',cmd='/bin/sh -c '+cmd)):
            store.add(key=f'linux.audit.{i}.{j}',activity_id='EASY-DISCOVERY-001',time=iso(et+timedelta(milliseconds=j)),host='USHQ-WEB-02',source='/var/log/audit/audit.log',sourcetype='linux_audit',raw=line,truth_label='malicious',technique=tech,question_tags='linux_discovery')

    # legitimate Tenable fan-out lookalike
    base=at(1,12,0,0)
    for i,(dst,port) in enumerate([(app,445),(dc,389),(eng,443),(fs,445),('10.48.30.20',443),('10.49.30.22',445),('10.50.30.25',443)]):
        uid2=zuid(f'tenable-{i}')
        store.add(key=f'tenable.conn.{i}',activity_id='EASY-RECON-BENIGN-002',time=iso(base+timedelta(seconds=i*2)),host='USNO-ZEEK-01',source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(base+timedelta(seconds=i*2)),uid2,H['USNO-TEN-01'],43000+i,dst,port,service='-',duration=.08,orig_bytes=96,resp_bytes=110),truth_label='benign',question_tags='recon,tenable')

    # 4. GitLab discovery/access from compromised web host through internal/cloud service path
    tg=at(0,16,9,12); git_ip='10.100.20.15'; uid=zuid('gitlab')
    store.add(key='git.dns',activity_id='EASY-GIT-001',time=iso(tg),host=us_hq_sensor,source='zeek:dns',sourcetype='zeek:dns',raw=zeek.dns(zts(tg),uid,web,53102,dns,'git.asteron.example',[git_ip]),truth_label='malicious',technique='T1083',question_tags='gitlab,cloud')
    store.add(key='git.conn',activity_id='EASY-GIT-001',time=iso(tg+timedelta(seconds=1)),host=us_hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(tg+timedelta(seconds=1)),uid,web,53103,git_ip,443,service='ssl',duration=4.2,orig_bytes=2421,resp_bytes=18222),truth_label='malicious',question_tags='gitlab,cloud')
    store.add(key='git.tls',activity_id='EASY-GIT-001',time=iso(tg+timedelta(seconds=1,milliseconds=15)),host=us_hq_sensor,source='zeek:ssl',sourcetype='zeek:ssl',raw=zeek.tls(zts(tg+timedelta(seconds=1,milliseconds=15)),uid,web,53103,git_ip,443,'git.asteron.example','t13d1516h2_e3b0c44298fc_001122334455'),truth_label='malicious',question_tags='gitlab,cloud')
    store.add(key='git.audit',activity_id='EASY-GIT-001',time=iso(tg+timedelta(seconds=2)),host='AWS-GITLAB-01',source='gitlab:audit',sourcetype='gitlab:audit',raw=apps.gitlab_audit(iso(tg+timedelta(seconds=2)),'svc-webdeploy','192.0.2.60','Project','repository_download','asteron/web-platform',{'auth_method':'deploy_token','project_id':732}),truth_label='malicious',technique='T1078',question_tags='gitlab,cloud')

    # 5. AWS enumeration using limited role from unexpected Asteron DMZ egress address
    ta=at(0,16,18,0); arn='arn:aws:sts::111122223333:assumed-role/WebPlatformDeployment/svc-webdeploy'
    for i,(ename,src,params) in enumerate([
        ('GetCallerIdentity','sts.amazonaws.com',{}),('ListBuckets','s3.amazonaws.com',{}),('DescribeInstances','ec2.amazonaws.com',{}),('GetObject','s3.amazonaws.com',{'bucketName':'asteron-web-config','key':'deploy/appsettings.json'})]):
        store.add(key=f'aws.{ename}',activity_id='EASY-AWS-001',time=iso(ta+timedelta(seconds=i*9)),host='AWS-CLOUDTRAIL-US',source='aws:cloudtrail',sourcetype='aws:cloudtrail',raw=apps.cloudtrail(iso(ta+timedelta(seconds=i*9)),ename,'192.0.2.60',arn,source=src,params=params),truth_label='malicious',technique='T1087' if i==0 else 'T1580',question_tags='aws,cloud_enumeration')

    # 6. Windows pivot to app via service account, WMI execution
    tw=at(1,13,44,16); login='0x6a91f'; pg_wmi=uuidg('wmi-parent'); pg_cmd=uuidg('wmi-cmd')
    store.add(key='win.4624.app',activity_id='EASY-WIN-PIVOT-001',time=iso(tw),host='USHQ-APP-07',source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=windows.security_4624(time=iso(tw),record_id=store.record_id_at('USHQ-APP-07','Security',tw),computer='USHQ-APP-07',user='svc-appdeploy',domain='US',logon_id=login,logon_type=3,ip=web,port='54218',process='-',auth='Kerberos'),truth_label='malicious',technique='T1078',question_tags='windows_pivot,service_account')
    uid=zuid('wmi-app')
    store.add(key='win.zeek.conn.135',activity_id='EASY-WIN-PIVOT-001',time=iso(tw-timedelta(milliseconds=220)),host=us_hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(tw-timedelta(milliseconds=220)),uid,web,54217,app,135,service='dce_rpc',duration=.43,orig_bytes=711,resp_bytes=931),truth_label='malicious',technique='T1047',question_tags='windows_pivot')
    store.add(key='win.zeek.dce',activity_id='EASY-WIN-PIVOT-001',time=iso(tw-timedelta(milliseconds=200)),host=us_hq_sensor,source='zeek:dce_rpc',sourcetype='zeek:dce_rpc',raw=zeek.dce_rpc(zts(tw-timedelta(milliseconds=200)),uid,web,app),truth_label='malicious',technique='T1047',question_tags='windows_pivot')
    store.add(key='win.4688.cmd',activity_id='EASY-WIN-PIVOT-001',time=iso(tw+timedelta(seconds=2)),host='USHQ-APP-07',source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=windows.security_4688(time=iso(tw+timedelta(seconds=2)),record_id=store.record_id_at('USHQ-APP-07','Security',tw+timedelta(seconds=2)),computer='USHQ-APP-07',subject_user='svc-appdeploy',new_pid_hex='0x1bd8',image=r'C:\Windows\System32\cmd.exe',parent=r'C:\Windows\System32\wbem\WmiPrvSE.exe',commandline=r'cmd.exe /c whoami /all',logon_id=login),truth_label='malicious',technique='T1047',question_tags='windows_pivot')
    store.add(key='win.sysmon.cmd',activity_id='EASY-WIN-PIVOT-001',time=iso(tw+timedelta(seconds=2,milliseconds=4)),host='USHQ-APP-07',source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_process(time=iso(tw+timedelta(seconds=2,milliseconds=4)),record_id=store.record_id_at('USHQ-APP-07','Microsoft-Windows-Sysmon/Operational',tw+timedelta(seconds=2,milliseconds=4)),computer='USHQ-APP-07',guid=pg_cmd,pid='7128',image=r'C:\Windows\System32\cmd.exe',commandline=r'cmd.exe /c whoami /all',parent_guid=pg_wmi,parent_pid='1640',parent_image=r'C:\Windows\System32\wbem\WmiPrvSE.exe',user=r'US\svc-appdeploy'),truth_label='malicious',technique='T1047',question_tags='windows_pivot')

    # Windows discovery commands
    cmds=[
        ('whoami /groups','T1069.001'),('net group "Domain Admins" /domain','T1069.002'),('nltest /dclist:us.asteron.local','T1018'),('ipconfig /all','T1016'),('netstat -ano','T1049'),('tasklist','T1057'),('sc query','T1007'),('net view \\USVA-FS-01','T1135')]
    for i,(cmd,tech) in enumerate(cmds):
        et=tw+timedelta(minutes=2,seconds=i*13); pid=7200+i; guid=uuidg('win-disc-'+str(i))
        store.add(key=f'win.disc.4688.{i}',activity_id='EASY-WIN-DISC-001',time=iso(et),host='USHQ-APP-07',source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=windows.security_4688(time=iso(et),record_id=store.record_id_at('USHQ-APP-07','Security',et),computer='USHQ-APP-07',subject_user='svc-appdeploy',new_pid_hex=hex(pid),image=r'C:\Windows\System32\cmd.exe',parent=r'C:\Windows\System32\wbem\WmiPrvSE.exe',commandline='cmd.exe /c '+cmd,logon_id=login),truth_label='malicious',technique=tech,question_tags='windows_discovery')
        store.add(key=f'win.disc.sysmon.{i}',activity_id='EASY-WIN-DISC-001',time=iso(et+timedelta(milliseconds=3)),host='USHQ-APP-07',source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_process(time=iso(et+timedelta(milliseconds=3)),record_id=store.record_id_at('USHQ-APP-07','Microsoft-Windows-Sysmon/Operational',et+timedelta(milliseconds=3)),computer='USHQ-APP-07',guid=guid,pid=str(pid),image=r'C:\Windows\System32\cmd.exe',commandline='cmd.exe /c '+cmd,parent_guid=pg_wmi,parent_pid='1640',parent_image=r'C:\Windows\System32\wbem\WmiPrvSE.exe',user=r'US\svc-appdeploy'),truth_label='malicious',technique=tech,question_tags='windows_discovery')
    # representative LDAP/SMB network discovery
    for i,(dst,port,svc) in enumerate([(dc,389,'ldap'),(dc,445,'smb'),(dns,53,'dns')]):
        et=tw+timedelta(minutes=3,seconds=i*5); uid=zuid('windisc-net'+str(i))
        if port==53:
            raw=zeek.dns(zts(et),uid,app,53010,dns,'us.asteron.local',[dc]); st='zeek:dns'; src='zeek:dns'
        else:
            raw=zeek.conn(zts(et),uid,app,53010+i,dst,port,service=svc,duration=.31,orig_bytes=712,resp_bytes=2501); st='zeek:conn'; src='zeek:conn'
        store.add(key=f'windisc.net.{i}',activity_id='EASY-WIN-DISC-001',time=iso(et),host=us_hq_sensor,source=src,sourcetype=st,raw=raw,truth_label='malicious',question_tags='windows_discovery')

    # endpoint detections (Trellix and Defender) as source telemetry, not ground-truth oracle
    store.add(key='trellix.web.alert',activity_id='EASY-ACCESS-001',time=iso(t2+timedelta(minutes=1)),host='USHQ-WEB-02',source='trellix:epo',sourcetype='trellix:epo',raw=json.dumps({'eventTime':iso(t2+timedelta(minutes=1)),'hostname':'USHQ-WEB-02','product':'Trellix Endpoint Security','threatName':'Web service spawned command shell','severity':'High','process':'/usr/bin/java','child_process':'/bin/sh','action':'WouldBlock','user':'asteronweb'},separators=(',',':')),truth_label='malicious',question_tags='endpoint_alert')
    store.add(key='defender.app.alert',activity_id='EASY-WIN-PIVOT-001',time=iso(tw+timedelta(minutes=1)),host='USHQ-APP-07',source='ms:defender:eventhub',sourcetype='ms:defender:eventhub',raw=apps.defender_event(iso(tw+timedelta(minutes=1)),'USHQ-APP-07','Unusual WMI initiated command shell','Medium',r'US\svc-appdeploy','WmiPrvSE.exe','cmd.exe','BehaviorObserved'),truth_label='malicious',question_tags='endpoint_alert')
    defender_alert_id='da'+uuid.uuid5(uuid.NAMESPACE_DNS,'asteron:defender:easy-wmi-pivot').hex[:30]
    store.add(key='defender.app.alertinfo',activity_id='EASY-WIN-PIVOT-001',time=iso(tw+timedelta(minutes=1,seconds=1)),host='USHQ-APP-07',source='ms:defender:eventhub',sourcetype='ms:defender:eventhub',raw=apps.defender_alert_info(iso(tw+timedelta(minutes=1,seconds=1)),defender_alert_id,'Suspicious WMI initiated command shell','Medium','Execution','T1047'),truth_label='malicious',technique='T1047',question_tags='endpoint_alert,defender_detection')
    store.add(key='defender.app.alertevidence',activity_id='EASY-WIN-PIVOT-001',time=iso(tw+timedelta(minutes=1,seconds=1,milliseconds=8)),host='USHQ-APP-07',source='ms:defender:eventhub',sourcetype='ms:defender:eventhub',raw=apps.defender_alert_evidence(iso(tw+timedelta(minutes=1,seconds=1,milliseconds=8)),defender_alert_id,'Suspicious WMI initiated command shell','Medium','USHQ-APP-07',r'US\svc-appdeploy','cmd.exe',r'C:\Windows\System32',r'cmd.exe /c whoami /all','WmiExec',detection_category='Execution',remediation_status='Observed',remediation_action='Alert'),truth_label='malicious',technique='T1047',question_tags='endpoint_alert,defender_detection')

    # 7. cross-site pivot via svc-engsync to USVA
    tx=at(2,15,14,33); login2='0x7c210'; uid=zuid('crosssite-winrm')
    store.add(key='cross.conn.hq',activity_id='EASY-XSPIVOT-001',time=iso(tx),host=us_hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(tx),uid,app,55112,eng,5985,service='http',duration=6.4,orig_bytes=8092,resp_bytes=12111),truth_label='malicious',technique='T1021.006',question_tags='cross_site,winrm')
    store.add(key='cross.conn.va',activity_id='EASY-XSPIVOT-001',time=iso(tx+timedelta(milliseconds=31)),host=us_va_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(tx+timedelta(milliseconds=31)),uid,app,55112,eng,5985,service='http',duration=6.4,orig_bytes=8092,resp_bytes=12111,local_orig=False,local_resp=True),truth_label='malicious',technique='T1021.006',question_tags='cross_site,winrm')
    store.add(key='cross.forti',activity_id='EASY-XSPIVOT-001',time=iso(tx),host='USHQ-FW-02',source='fortigate_traffic',sourcetype='fortigate_traffic',raw=network_devices.fortigate(tx.strftime('%Y-%m-%d'),tx.strftime('%H:%M:%S'),'USHQ-FW-02',app,eng,55112,5985,'accept',220,'app-zone','vpn-zone','HTTP',8092,12111),truth_label='malicious',technique='T1021.006',question_tags='cross_site,firewall')
    store.add(key='cross.asa',activity_id='EASY-XSPIVOT-001',time=iso(tx+timedelta(milliseconds=20)),host='USVA-FW-03',source='cisco:asa',sourcetype='cisco:asa',raw=network_devices.cisco_asa(tx.strftime('%b %d %Y %H:%M:%S'),'USVA-FW-03','302013',app,55112,eng,5985,'Built inbound TCP connection'),truth_label='malicious',technique='T1021.006',question_tags='cross_site,firewall')
    store.add(key='cross.4624',activity_id='EASY-XSPIVOT-001',time=iso(tx+timedelta(seconds=1)),host='USVA-ENG-APP-01',source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=windows.security_4624(time=iso(tx+timedelta(seconds=1)),record_id=store.record_id_at('USVA-ENG-APP-01','Security',tx+timedelta(seconds=1)),computer='USVA-ENG-APP-01',user='svc-engsync',domain='US',logon_id=login2,logon_type=3,ip=app,port='55112',auth='Kerberos'),truth_label='malicious',technique='T1078',question_tags='cross_site,service_account')

    # Engineering file access and direct Easy exfil (no staging)
    tf=at(3,16,10,2); file_path=r'\\USVA-FS-01\Engineering\Grid_Modernization\2026\regional_engineering_package.pdf'; uid=zuid('smb-file')
    store.add(key='eng.smb',activity_id='EASY-COLLECT-001',time=iso(tf),host=us_va_sensor,source='zeek:smb_files',sourcetype='zeek:smb_files',raw=zeek.smb(zts(tf),uid,eng,fs,r'\\USVA-FS-01\Engineering\Grid_Modernization\2026','regional_engineering_package.pdf'),truth_label='malicious',technique='T1005',question_tags='collection')
    # exfil dns + conn + tls + sysmon network + dlp + egress fw
    te=tf+timedelta(minutes=7,seconds=28); uid2=zuid('easy-exfil')
    store.add(key='exfil.dns',activity_id='EASY-EXFIL-001',time=iso(te),host=us_va_sensor,source='zeek:dns',sourcetype='zeek:dns',raw=zeek.dns(zts(te),uid2,eng,54002,'10.47.10.20',CFG['actor_exfil_domain'],[exfil]),truth_label='malicious',technique='T1041',question_tags='exfiltration')
    store.add(key='exfil.conn',activity_id='EASY-EXFIL-001',time=iso(te+timedelta(seconds=1)),host=us_va_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(te+timedelta(seconds=1)),uid2,eng,54003,exfil,443,service='ssl',duration=188.7,orig_bytes=CFG['exfil_bytes'],resp_bytes=242819),truth_label='malicious',technique='T1041',question_tags='exfiltration')
    store.add(key='exfil.tls',activity_id='EASY-EXFIL-001',time=iso(te+timedelta(seconds=1,milliseconds=20)),host=us_va_sensor,source='zeek:ssl',sourcetype='zeek:ssl',raw=zeek.tls(zts(te+timedelta(seconds=1,milliseconds=20)),uid2,eng,54003,exfil,443,CFG['actor_exfil_domain'],'t13d1517h2_4c3a1f4bd870_3398f65bc4af','Fcert-exfil'),truth_label='malicious',technique='T1041',question_tags='exfiltration')
    store.add(key='exfil.sysmon',activity_id='EASY-EXFIL-001',time=iso(te+timedelta(seconds=1,milliseconds=10)),host='USVA-ENG-APP-01',source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_network(time=iso(te+timedelta(seconds=1,milliseconds=10)),record_id=store.record_id_at('USVA-ENG-APP-01','Microsoft-Windows-Sysmon/Operational',te+timedelta(seconds=1,milliseconds=10)),computer='USVA-ENG-APP-01',guid=uuidg('eng-browser'),pid='6140',image=r'C:\Program Files\Asteron\EngineeringSync\engsync.exe',user=r'US\svc-engsync',src_ip=eng,src_port='54003',dst_ip=exfil,dst_port='443',dst_host=CFG['actor_exfil_domain']),truth_label='malicious',technique='T1041',question_tags='exfiltration')
    store.add(key='exfil.dlp',activity_id='EASY-EXFIL-001',time=iso(te+timedelta(seconds=2)),host='USVA-DLP-01',source='dlp:events',sourcetype='dlp:events',raw=apps.dlp(iso(te+timedelta(seconds=2)),r'US\svc-engsync','USVA-ENG-APP-01','regional_engineering_package.pdf',CFG['exfil_bytes'],CFG['actor_exfil_domain'],'Engineering Sensitive - External Upload'),truth_label='malicious',technique='T1041',question_tags='exfiltration,dlp')
    store.add(key='exfil.pan',activity_id='EASY-EXFIL-001',time=iso(te+timedelta(seconds=1)),host='USVA-FW-02',source='pan:traffic',sourcetype='pan:traffic',raw=network_devices.palo_alto(te.strftime('%Y/%m/%d %H:%M:%S'),'PA-USVA-002',eng,exfil,54003,443,'allow','ENGINEERING-WEB-EGRESS','engineering','untrust',bytes_out=CFG['exfil_bytes'],bytes_in=242819),truth_label='malicious',technique='T1041',question_tags='exfiltration,firewall')

    # benign DLP and badge events to prevent oracle behavior
    tb=at(3,14,1,0)
    store.add(key='dlp.benign',activity_id='EASY-BENIGN-DLP-001',time=iso(tb),host='USHQ-DLP-01',source='dlp:events',sourcetype='dlp:events',raw=apps.dlp(iso(tb),r'US\rpatel','USHQ-WS-0175','vendor_network_diagram.pdf',18300421,'files.partner.example','Engineering Sensitive - External Upload','medium','allow_with_justification'),truth_label='benign',question_tags='dlp,false_positive')
    for i,(ts,badge,emp,site,reader) in enumerate([
        (at(1,12,15,0),'B-104882','E104882','USHQ','HQ-LOBBY-01'),
        (at(3,12,2,0),'B-108211','E108211','USVA','VA-ENG-ENTRY-02')]):
        store.add(key=f'badge.{i}',activity_id='EASY-BADGE-BASELINE',time=iso(ts),host=site+'-PACS-01',source='pacs:access',sourcetype='pacs:access',raw=apps.badge(iso(ts),badge,emp,site,reader),truth_label='benign',question_tags='physical_access')


def random_business_utc(rng, site_code, start_date, day_offset):
    s=SITE_BY_CODE[site_code]; tz=ZoneInfo(s['timezone'])
    local=datetime(start_date.year,start_date.month,start_date.day,8,0,tzinfo=tz)+timedelta(days=day_offset)
    local += timedelta(minutes=rng.randint(-90,600))
    return local.astimezone(timezone.utc)

def add_background(store, count):
    rng=random.Random(CFG['seed'])
    sites=CFG['scope_sites']; start=CTX.start
    user_hosts=[]
    for site in sites:
        sec=int(SITE_BY_CODE[site]['cidr'].split('.')[1]);
        for n in range(1,25): user_hosts.append((f'{site}-WS-{n:04d}',f'10.{sec}.40.{20+n}',site))
    services=[('microsoft.com',443),('servicenow.asteron.example',443),('git.asteron.example',443),('print.asteron.example',445),('wsus.asteron.example',8531)]
    for i in range(count):
        host,ip,site=rng.choice(user_hosts); day=rng.randrange(CTX.days); dt=random_business_utc(rng,site,start,day)
        campaign_start=CTX.start; campaign_end=CTX.end
        while dt < campaign_start:
            dt += timedelta(days=1)
        while dt > campaign_end:
            dt -= timedelta(days=1)
        kind=rng.choices(['zeek','winlogon','winproc','firewall','badge'],[45,20,15,15,5])[0]
        if kind=='zeek':
            name,port=rng.choice(services); dst='10.45.30.'+str(rng.randint(20,80)) if name.endswith('asteron.example') else '13.107.246.'+str(rng.randint(10,220)); uid=zuid(f'bg-{i}')
            store.add(key=f'bg.zeek.{i}',activity_id='BACKGROUND',time=iso(dt),host=f'{site}-ZEEK-01',source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(dt),uid,ip,rng.randint(49152,65500),dst,port,service='ssl' if port==443 else '-',duration=round(rng.uniform(.05,12),3),orig_bytes=rng.randint(100,9000),resp_bytes=rng.randint(200,80000)),truth_label='background')
        elif kind=='winlogon':
            user='user'+str(rng.randint(100,999));
            store.add(key=f'bg.4624.{i}',activity_id='BACKGROUND',time=iso(dt),host=host,source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=windows.security_4624(time=iso(dt),record_id=store.record_id_at(host,'Security',dt),computer=host,user=user,domain='US',logon_id=hex(rng.randint(0x10000,0xffffff)),logon_type=2,ip='-',port='-',auth='Kerberos'),truth_label='background')
        elif kind=='winproc':
            user='US\\user'+str(rng.randint(100,999)); image=r'C:\Windows\System32\svchost.exe' if rng.random()<.55 else r'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE'; parent=r'C:\Windows\System32\services.exe' if 'svchost' in image else r'C:\Windows\explorer.exe'; guid=uuidg(f'bgproc-{i}')
            store.add(key=f'bg.proc.{i}',activity_id='BACKGROUND',time=iso(dt),host=host,source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_process(time=iso(dt),record_id=store.record_id_at(host,'Microsoft-Windows-Sysmon/Operational',dt),computer=host,guid=guid,pid=str(rng.randint(600,15000)),image=image,commandline=image,parent_guid=uuidg('parent-'+str(i)),parent_pid=str(rng.randint(400,4000)),parent_image=parent,user=user),truth_label='background')
        elif kind=='firewall':
            dst='13.107.246.'+str(rng.randint(10,220)); p=rng.randint(49152,65500)
            if i%3==0:
                raw=network_devices.palo_alto(dt.strftime('%Y/%m/%d %H:%M:%S'),'PA-'+site+'-001',ip,dst,p,443,'allow','USER-WEB','users','untrust',bytes_out=rng.randint(100,4000),bytes_in=rng.randint(500,90000)); st='pan:traffic'; fw=site+'-FW-01'; src='pan:traffic'
            elif i%3==1:
                raw=network_devices.fortigate(dt.strftime('%Y-%m-%d'),dt.strftime('%H:%M:%S'),site+'-FW-02',ip,dst,p,443,'accept',100,'users','wan','HTTPS',rng.randint(100,4000),rng.randint(500,90000)); st='fortigate_traffic'; fw=site+'-FW-02'; src='fortigate_traffic'
            else:
                raw=network_devices.cisco_asa(dt.strftime('%b %d %Y %H:%M:%S'),site+'-FW-03','302013',ip,p,dst,443); st='cisco:asa'; fw=site+'-FW-03'; src='cisco:asa'
            store.add(key=f'bg.fw.{i}',activity_id='BACKGROUND',time=iso(dt),host=fw,source=src,sourcetype=st,raw=raw,truth_label='background')
        else:
            badge='B-'+str(rng.randint(100000,199999)); emp='E'+str(rng.randint(100000,199999))
            store.add(key=f'bg.badge.{i}',activity_id='BACKGROUND',time=iso(dt),host=site+'-PACS-01',source='pacs:access',sourcetype='pacs:access',raw=apps.badge(iso(dt),badge,emp,site,site+'-ENTRY-'+str(rng.randint(1,8))),truth_label='background')


def main():
    global CFG, CTX
    ap=argparse.ArgumentParser(description='Generate Asteron/SILK SPECTER scenario telemetry')
    ap.add_argument('--scenario',choices=['easy','medium','hard'],default='easy')
    ap.add_argument('--start',help='Override scenario UTC start (ISO-8601). Event chronology remains relative to day 0.')
    ap.add_argument('--end',help='Override scenario UTC end (ISO-8601). Must contain the scenario timeline.')
    ap.add_argument('--output',help='Output directory; default dataset/<scenario>')
    ap.add_argument('--background-events',type=int,default=None,help='Override scenario generation.background_events')
    ap.add_argument('--enterprise-background-events',type=int,default=None,help='Override scenario generation.enterprise_background_events')
    ap.add_argument('--allow-authoring',action='store_true',help='Build an authoring scenario for validation without marking it validated')
    args=ap.parse_args()

    CTX=load_scenario(ROOT,args.scenario,args.start,args.end)
    CFG=CTX.config
    background_events, enterprise_background_events = resolve_generation_counts(
        CFG, args.background_events, args.enterprise_background_events
    )
    if CTX.status != 'validated' and not args.allow_authoring:
        raise SystemExit(
            f"Scenario {args.scenario!r} is status={CTX.status!r}. "
            "Use --allow-authoring only for validation builds; do not mark it validated until Splunk checks pass."
        )
    store=EventStore(args.scenario)
    add_background(store,background_events)
    scoped_sites=[SITE_BY_CODE[c] for c in CFG['scope_sites']]
    add_enterprise_background(store,enterprise_background_events,scoped_sites,seed=CFG['seed']+1,campaign_start=CTX.start,campaign_end=CTX.end)
    add_defender_detection_background(store,scoped_sites,alert_count=180,seed=CFG['seed']+11,campaign_start=CTX.start,campaign_end=CTX.end)
    if args.scenario == 'easy':
        add_attack(store)
        add_attack_corroboration(store,CFG)
        add_attack_expansion(store,CFG)
    elif args.scenario == 'medium':
        build_medium_campaign(store, CTX, {'config': CFG, 'sites': scoped_sites})
    elif args.scenario == 'hard':
        build_hard_campaign(store, CTX, {'config': CFG, 'sites': scoped_sites})
    out=Path(args.output or ROOT/'dataset'/args.scenario); out.parent.mkdir(parents=True,exist_ok=True)
    # Hard fail if any event escapes the declared scenario window.
    for event in store.events:
        CTX.require_in_window(parse_utc(event.time))
    summary=store.write(out)
    summary['window_start']=CFG['start']; summary['window_end']=CFG['end']; summary['status']=CTX.status
    summary['generation']={
        'background_events': background_events,
        'enterprise_background_events': enterprise_background_events,
    }
    (out/'manifest.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))

if __name__=='__main__': main()
