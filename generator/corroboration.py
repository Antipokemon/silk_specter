from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json, uuid

from renderers import windows, linux, zeek, network_devices, apps
from core.scenario import ScenarioContext


def iso(dt): return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
def zts(dt): return dt.timestamp()
def syslog_stamp(dt): return dt.astimezone(timezone.utc).strftime('%b %d %H:%M:%S')
def uuidg(name): return '{'+str(uuid.uuid5(uuid.NAMESPACE_DNS,'asteron:corr:'+name))+'}'
def zuid(name): return 'C'+uuid.uuid5(uuid.NAMESPACE_DNS,'zeek:corr:'+name).hex[:17]
def at(cfg,day,hour=0,minute=0,second=0,microsecond=0): return ScenarioContext.from_dict(cfg.get('difficulty','easy'),cfg).at(day,hour,minute,second,microsecond)


def add_attack_corroboration(store, cfg):
    H=cfg['hosts']; web=H['USHQ-WEB-02']; app=H['USHQ-APP-07']; dc=H['USHQ-DC-02']; eng=H['USVA-ENG-APP-01']; fs=H['USVA-FS-01']
    hq_sensor='USHQ-ZEEK-01'; va_sensor='USVA-ZEEK-01'

    # Web shell file seen by network/file analysis and endpoint follow-on.
    t=at(cfg,0,15,23,0)
    uid=zuid('webshell-file'); fuid='F'+uuid.uuid5(uuid.NAMESPACE_DNS,'webshell-file').hex[:15]
    store.add(key='corr.webshell.files',activity_id='EASY-ACCESS-001',time=iso(t),host=hq_sensor,source='zeek:files',sourcetype='zeek:files',
              raw=zeek.files(zts(t),fuid,uid,[cfg['actor_initial_ip']],[web],'HTTP','application/octet-stream','.runtime/status',14832,'8b76c4d0f10e9d92f2bc85ca9c5fa006c4944bd169d066204214c882055153fc'),
              truth_label='malicious',technique='T1505.003',question_tags='initial_access,webshell,file_create')

    # Linux process makes network connections involved in the GitLab/cloud pivot.
    tg=at(cfg,0,16,9,13)
    store.add(key='corr.git.linuxnet',activity_id='EASY-GIT-001',time=iso(tg),host='USHQ-WEB-02',source='/var/log/syslog',sourcetype='syslog',
              raw=linux.linux_sysmon_network(syslog_time=syslog_stamp(tg),iso_time=iso(tg),record_id=store.record_id_at('USHQ-WEB-02','Linux-Sysmon/Operational',tg),host='USHQ-WEB-02',guid=uuidg('curl-git'),pid=18512,image='/usr/bin/curl',src_ip=web,src_port=53103,dst_ip='10.100.20.15',dst_port=443,user='www-data'),
              truth_label='malicious',technique='T1078',question_tags='gitlab,cloud,process_network')

    # Cloud network corroboration around GitLab and cloud enumeration.
    for n,(ts,src,dst,sport,dport,bytes_count) in enumerate([
        (at(cfg,0,16,9,13),web,'10.100.20.15',53103,443,20643),
        (at(cfg,0,16,18,20),'10.100.20.15','52.95.245.12',44220,443,12988),
    ]):
        start=int(ts.timestamp()); end=start+5
        store.add(key=f'corr.awsvpc.{n}',activity_id='EASY-AWS-001',time=iso(ts),host='AWS-GITLAB-PROD',source='aws:vpcflow',sourcetype='aws:cloudwatchlogs:vpcflow',
                  raw=apps.aws_vpc_flow(5,'111122223333','eni-0a51b001',src,dst,sport,dport,6,22,bytes_count,start,end),truth_label='malicious',technique='T1580',question_tags='aws,cloud_enumeration,network')

    # Kerberos evidence for the Windows service-account pivots.
    tw=at(cfg,1,15,31,18)
    store.add(key='corr.win4769.app',activity_id='EASY-WIN-PIVOT-001',time=iso(tw-timedelta(seconds=1)),host='USHQ-DC-02',source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',
              raw=windows.security_4769(time=iso(tw-timedelta(seconds=1)),record_id=store.record_id_at('USHQ-DC-02','Security',tw-timedelta(seconds=1)),computer='USHQ-DC-02',user='svc-appdeploy',service='HOST/USHQ-APP-07.us.asteron.local',client_ip='::ffff:'+web),truth_label='malicious',technique='T1078',question_tags='windows_pivot,kerberos')

    # Domain discovery produces DNS and service-ticket patterns.
    td=at(cfg,1,15,34,5)
    queries=[('ushq-dc-02.us.asteron.local',dc),('ushq-fs-03.us.asteron.local','10.44.20.31'),('usva-eng-app-01.us.asteron.local',eng)]
    for i,(q,a) in enumerate(queries):
        dt=td+timedelta(seconds=i*4); uid=zuid('disc-dns-'+str(i))
        store.add(key=f'corr.windisc.dns.{i}',activity_id='EASY-WIN-DISC-001',time=iso(dt),host=hq_sensor,source='zeek:dns',sourcetype='zeek:dns',
                  raw=zeek.dns(zts(dt),uid,app,53000+i,H['USHQ-DNS-01'],q,[a]),truth_label='malicious',technique='T1018',question_tags='windows_discovery,dns')

    # Cross-site service ticket and connection context.
    tx=at(cfg,2,14,42,26)
    store.add(key='corr.cross.4769',activity_id='EASY-XSPIVOT-001',time=iso(tx-timedelta(seconds=1)),host='USHQ-DC-02',source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',
              raw=windows.security_4769(time=iso(tx-timedelta(seconds=1)),record_id=store.record_id_at('USHQ-DC-02','Security',tx-timedelta(seconds=1)),computer='USHQ-DC-02',user='svc-engsync',service='HTTP/USVA-ENG-APP-01.us.asteron.local',client_ip='::ffff:'+app),truth_label='malicious',technique='T1078',question_tags='cross_site,kerberos')

    # Collection produces SMB network metadata on both sides and file event.
    tf=at(cfg,3,16,10,2)
    uid=zuid('collect-smb-conn')
    store.add(key='corr.collect.conn',activity_id='EASY-COLLECT-001',time=iso(tf-timedelta(milliseconds=20)),host=va_sensor,source='zeek:conn',sourcetype='zeek:conn',
              raw=zeek.conn(zts(tf-timedelta(milliseconds=20)),uid,eng,52144,fs,445,service='smb',duration=12.8,orig_bytes=131112,resp_bytes=24791321),truth_label='malicious',technique='T1005',question_tags='collection,network')

    # Additional endpoint file observation on the engineering system.
    store.add(key='corr.collect.sysmonfile',activity_id='EASY-COLLECT-001',time=iso(tf+timedelta(seconds=2)),host='USVA-ENG-APP-01',source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',
              raw=windows.sysmon_file(time=iso(tf+timedelta(seconds=2)),record_id=store.record_id_at('USVA-ENG-APP-01','Microsoft-Windows-Sysmon/Operational',tf+timedelta(seconds=2)),computer='USVA-ENG-APP-01',guid=uuidg('engsync-file'),pid='6140',image=r'C:\Program Files\Asteron\EngineeringSync\engsync.exe',target=r'C:\ProgramData\Asteron\EngineeringSync\regional_engineering_package.pdf'),truth_label='malicious',technique='T1005',question_tags='collection,file')

    # Exfil certificate/file metadata gives alternative evidence without decrypting all flows.
    te=tf+timedelta(minutes=7,seconds=29)
    store.add(key='corr.exfil.x509',activity_id='EASY-EXFIL-001',time=iso(te),host=va_sensor,source='zeek:x509',sourcetype='zeek:x509',
              raw=zeek.x509(zts(te),'Fcert-exfil',3,'01AA77',f'CN={cfg["actor_exfil_domain"]}',f'CN=Cloud TLS RSA CA',zts(te-timedelta(days=20)),zts(te+timedelta(days=70)),san_dns=[cfg['actor_exfil_domain']]),truth_label='malicious',technique='T1041',question_tags='exfiltration,tls,certificate')

    # Benign MFT transfer and approved change ticket around the same day are deliberate lookalikes.
    tb=at(cfg,3,15,20,0)
    store.add(key='corr.benign.mft',activity_id='EASY-BENIGN-MFT-001',time=iso(tb),host='USNO-MFT-01',source='mft:transfer',sourcetype='mft:transfer',
              raw=apps.mft_transfer(iso(tb),r'US\adm-rpatel','USHQ-PAW-02','vendor_patch_bundle.zip',88422110,'gov-exchange.example','upload','success','tx-approved-0001'),truth_label='benign',question_tags='exfiltration,false_positive,mft')
    store.add(key='corr.benign.snow',activity_id='EASY-BENIGN-MFT-001',time=iso(tb-timedelta(minutes=20)),host='SAAS-SERVICENOW',source='servicenow:audit',sourcetype='servicenow:audit',
              raw=apps.servicenow_audit(iso(tb-timedelta(minutes=20)),r'US\adm-rpatel','approve','change_request','CHG0048219','10.44.50.52','Approved vendor patch transfer to government exchange'),truth_label='benign',question_tags='change_management,false_positive')
