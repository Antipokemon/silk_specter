from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json, uuid

from renderers import windows, linux, zeek, network_devices, apps
from core.scenario import ScenarioContext


def iso(dt): return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
def zts(dt): return dt.timestamp()
def syslog_stamp(dt): return dt.astimezone(timezone.utc).strftime('%b %d %H:%M:%S')
def uuidg(name): return '{'+str(uuid.uuid5(uuid.NAMESPACE_DNS,'asteron:expand:'+name))+'}'
def zuid(name): return 'C'+uuid.uuid5(uuid.NAMESPACE_DNS,'zeek:expand:'+name).hex[:17]
def at(cfg,day,hour=0,minute=0,second=0,microsecond=0): return ScenarioContext.from_dict(cfg.get('difficulty','easy'),cfg).at(day,hour,minute,second,microsecond)


def _linux_exec(store, *, key, activity, dt, host, pid, ppid, image, cmd, user, technique, tags, parent='/usr/bin/java'):
    guid=uuidg(key)
    store.add(key=key+'.sysmon',activity_id=activity,time=iso(dt),host=host,source='/var/log/syslog',sourcetype='syslog',
              raw=linux.linux_sysmon_process_generic(syslog_time=syslog_stamp(dt),iso_time=iso(dt),record_id=store.record_id_at(host,'Linux-Sysmon/Operational',dt),host=host,guid=guid,pid=pid,ppid=ppid,image=image,cmd=cmd,user=user,parent_image=parent,parent_cmd=parent),
              truth_label='malicious',technique=technique,question_tags=tags)
    uid=0 if user=='root' else 33
    for j,line in enumerate(linux.audit_exec(epoch=int(dt.timestamp()),serial=800000+pid,host=host,pid=pid,ppid=ppid,uid=uid,exe=image,cmd=cmd)):
        store.add(key=f'{key}.audit.{j}',activity_id=activity,time=iso(dt+timedelta(milliseconds=j+1)),host=host,source='/var/log/audit/audit.log',sourcetype='linux_audit',raw=line,
                  truth_label='malicious',technique=technique,question_tags=tags)
    return guid


def _win_proc(store, *, key, activity, dt, host, user, pid, image, cmd, parent, technique, tags, logon='0x6a91f'):
    guid=uuidg(key); pg=uuidg(key+'.parent')
    store.add(key=key+'.4688',activity_id=activity,time=iso(dt),host=host,source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',
              raw=windows.security_4688(time=iso(dt),record_id=store.record_id_at(host,'Security',dt),computer=host,subject_user=user.split('\\')[-1],new_pid_hex=hex(pid),image=image,parent=parent,commandline=cmd,logon_id=logon),
              truth_label='malicious',technique=technique,question_tags=tags)
    store.add(key=key+'.sysmon',activity_id=activity,time=iso(dt+timedelta(milliseconds=3)),host=host,source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',
              raw=windows.sysmon_process(time=iso(dt+timedelta(milliseconds=3)),record_id=store.record_id_at(host,'Microsoft-Windows-Sysmon/Operational',dt+timedelta(milliseconds=3)),computer=host,guid=guid,pid=str(pid),image=image,commandline=cmd,parent_guid=pg,parent_pid='1640',parent_image=parent,user=user),
              truth_label='malicious',technique=technique,question_tags=tags)
    return guid


def add_attack_expansion(store, cfg):
    """Expand Easy from a skeleton to a full lifecycle campaign.

    These are additional observations around the existing canonical attack.
    The original answer-bearing events are not changed.
    """
    H=cfg['hosts']; web=H['USHQ-WEB-02']; app=H['USHQ-APP-07']; dc=H['USHQ-DC-02']; dns=H['USHQ-DNS-01']; eng=H['USVA-ENG-APP-01']; fs=H['USVA-FS-01']
    actor=cfg['actor_initial_ip']; pub=cfg['public_vip']; hq_sensor='USHQ-ZEEK-01'; va_sensor='USVA-ZEEK-01'

    # ------------------------------------------------------------------
    # Reconnaissance: actor follows public exposure with measured probing.
    # ------------------------------------------------------------------
    base=at(cfg,0,14,42,0)
    recon_paths=['/','/robots.txt','/favicon.ico','/api/status','/api/version','/health','/login','/assets/app.js','/.well-known/security.txt','/api/render']
    for i in range(20):
        dt=base+timedelta(seconds=i*37); uid=zuid(f'recon-{i}'); sport=47000+i
        path=recon_paths[i%len(recon_paths)]; status=200 if path not in ['/api/version','/.well-known/security.txt'] else 404
        store.add(key=f'exp.recon.{i}.conn',activity_id='EASY-RECON-ACTOR-001',time=iso(dt),host=hq_sensor,source='zeek:conn',sourcetype='zeek:conn',
                  raw=zeek.conn(zts(dt),uid,actor,sport,web,443,service='ssl',duration=.3+i*.02,orig_bytes=280+i*13,resp_bytes=900+i*31,local_orig=False,local_resp=True),truth_label='malicious',technique='T1595',question_tags='recon,external')
        store.add(key=f'exp.recon.{i}.tls',activity_id='EASY-RECON-ACTOR-001',time=iso(dt+timedelta(milliseconds=8)),host=hq_sensor,source='zeek:ssl',sourcetype='zeek:ssl',
                  raw=zeek.tls(zts(dt+timedelta(milliseconds=8)),uid,actor,sport,web,443,'portal.asteron.example',f't13d1516h2_{i:012x}_11aa22bb33cc'),truth_label='malicious',technique='T1595',question_tags='recon,external')
        store.add(key=f'exp.recon.{i}.http',activity_id='EASY-RECON-ACTOR-001',time=iso(dt+timedelta(milliseconds=60)),host=hq_sensor,source='zeek:http',sourcetype='zeek:http',
                  raw=zeek.http(zts(dt+timedelta(milliseconds=60)),uid,actor,sport,web,443,'GET','portal.asteron.example',path,status,'Mozilla/5.0',resp_len=300+i*29),truth_label='malicious',technique='T1595',question_tags='recon,external')
        store.add(key=f'exp.recon.{i}.waf',activity_id='EASY-RECON-ACTOR-001',time=iso(dt+timedelta(milliseconds=61)),host='AWS-WEB-WAF-01',source='aws:waf',sourcetype='aws:waf',
                  raw=apps.waf(iso(dt+timedelta(milliseconds=61)),actor,'portal.asteron.example',path,status,'ALLOW','PublicPortalDefault',f'req-recon-{i:03d}'),truth_label='malicious',technique='T1595',question_tags='recon,external')
        store.add(key=f'exp.recon.{i}.fw',activity_id='EASY-RECON-ACTOR-001',time=iso(dt),host='USHQ-FW-01',source='pan:traffic',sourcetype='pan:traffic',
                  raw=network_devices.palo_alto(dt.strftime('%Y/%m/%d %H:%M:%S'),'PA-USHQ-001',actor,pub,sport,443,'allow','PUBLIC-WEB','untrust','dmz',bytes_out=280+i*13,bytes_in=900+i*31,nat_dst=web),truth_label='malicious',technique='T1595',question_tags='recon,external')

    # ------------------------------------------------------------------
    # Initial access: repeated interaction surrounding the canonical exploit.
    # ------------------------------------------------------------------
    base=at(cfg,0,15,20,0)
    for i in range(10):
        dt=base+timedelta(seconds=i*19); uid=zuid(f'access-prep-{i}'); sport=48600+i
        uri='/api/render' if i>=5 else '/api/status'
        method='POST' if i>=5 else 'GET'; status=500 if i in (6,7) else 200
        store.add(key=f'exp.access.{i}.conn',activity_id='EASY-ACCESS-EXPANDED',time=iso(dt),host=hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(dt),uid,actor,sport,web,443,service='ssl',duration=1.1,orig_bytes=1200+i*101,resp_bytes=800+i*47,local_orig=False,local_resp=True),truth_label='malicious',technique='T1190',question_tags='initial_access')
        store.add(key=f'exp.access.{i}.http',activity_id='EASY-ACCESS-EXPANDED',time=iso(dt+timedelta(milliseconds=50)),host=hq_sensor,source='zeek:http',sourcetype='zeek:http',raw=zeek.http(zts(dt+timedelta(milliseconds=50)),uid,actor,sport,web,443,method,'portal.asteron.example',uri,status,'Mozilla/5.0',resp_len=220+i*10),truth_label='malicious',technique='T1190',question_tags='initial_access')
        store.add(key=f'exp.access.{i}.waf',activity_id='EASY-ACCESS-EXPANDED',time=iso(dt+timedelta(milliseconds=55)),host='AWS-WEB-WAF-01',source='aws:waf',sourcetype='aws:waf',raw=apps.waf(iso(dt+timedelta(milliseconds=55)),actor,'portal.asteron.example',uri,status,'COUNT' if i>=6 else 'ALLOW','AppInputAnomaly' if i>=6 else 'PublicPortalDefault',f'req-access-{i:03d}'),truth_label='malicious',technique='T1190',question_tags='initial_access')
        store.add(key=f'exp.access.{i}.fw',activity_id='EASY-ACCESS-EXPANDED',time=iso(dt),host='USHQ-FW-01',source='pan:traffic',sourcetype='pan:traffic',raw=network_devices.palo_alto(dt.strftime('%Y/%m/%d %H:%M:%S'),'PA-USHQ-001',actor,pub,sport,443,'allow','PUBLIC-WEB','untrust','dmz',bytes_out=1200+i*101,bytes_in=800+i*47,nat_dst=web),truth_label='malicious',technique='T1190',question_tags='initial_access')

    # ------------------------------------------------------------------
    # Execution: interactive web-shell sessions using native utilities.
    # ------------------------------------------------------------------
    linux_cmds=[
        ('/usr/bin/id','id','T1059.004'),('/usr/bin/uname','uname -a','T1059.004'),('/usr/sbin/ip','ip addr','T1059.004'),('/usr/sbin/ip','ip route','T1059.004'),
        ('/usr/bin/ss','ss -plant','T1059.004'),('/usr/bin/ps','ps -ef','T1059.004'),('/usr/bin/hostname','hostname -f','T1059.004'),('/usr/bin/who','who','T1059.004'),
        ('/usr/bin/env','env','T1059.004'),('/usr/bin/ls','ls -la /srv/asteron-web','T1059.004'),('/usr/bin/find','find /srv/asteron-web -maxdepth 2 -type f','T1059.004'),('/usr/bin/cat','cat /etc/os-release','T1059.004'),
        ('/usr/bin/cat','cat /etc/resolv.conf','T1059.004'),('/usr/bin/systemctl','systemctl --type=service --state=running','T1059.004'),('/usr/bin/df','df -h','T1059.004'),('/usr/bin/mount','mount','T1059.004'),
        ('/usr/bin/getent','getent passwd','T1059.004'),('/usr/bin/getent','getent group','T1059.004'),('/usr/bin/last','last -n 10','T1059.004'),('/usr/bin/journalctl','journalctl -n 25','T1059.004'),
        ('/usr/bin/which','which python3','T1059.004'),('/usr/bin/which','which curl','T1059.004'),('/usr/bin/ls','ls -la /etc/asteron','T1059.004'),('/usr/bin/ls','ls -la /var/lib/asteron','T1059.004'),
    ]
    base=at(cfg,0,15,24,30)
    for i,(image,cmd,tech) in enumerate(linux_cmds):
        _linux_exec(store,key=f'exp.exec.{i}',activity='EASY-EXECUTION-001',dt=base+timedelta(seconds=i*11),host='USHQ-WEB-02',pid=19000+i,ppid=18422,image=image,cmd=cmd,user='www-data',technique=tech,tags='execution,webshell')

    # ------------------------------------------------------------------
    # Persistence: repeated web-shell callbacks plus valid-account reuse.
    # ------------------------------------------------------------------
    persistence_times=[
        at(cfg,0,18,14,0), at(cfg,1,13,8,0),
        at(cfg,1,17,45,0), at(cfg,2,14,2,0),
        at(cfg,2,19,11,0), at(cfg,3,13,20,0),
        at(cfg,3,18,4,0), at(cfg,4,14,9,0),
        at(cfg,4,17,2,0), at(cfg,4,19,20,0),
        at(cfg,1,14,18,0), at(cfg,2,16,28,0),
    ]
    for i,dt in enumerate(sorted(persistence_times)):
        uid=zuid(f'persist-{i}'); sport=49000+i
        store.add(key=f'exp.persist.{i}.conn',activity_id='EASY-PERSIST-001',time=iso(dt),host=hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(dt),uid,actor,sport,web,443,service='ssl',duration=4.1,orig_bytes=1100+i*20,resp_bytes=1800+i*31,local_orig=False,local_resp=True),truth_label='malicious',technique='T1505.003',question_tags='persistence,webshell')
        store.add(key=f'exp.persist.{i}.tls',activity_id='EASY-PERSIST-001',time=iso(dt+timedelta(milliseconds=8)),host=hq_sensor,source='zeek:ssl',sourcetype='zeek:ssl',raw=zeek.tls(zts(dt+timedelta(milliseconds=8)),uid,actor,sport,web,443,'portal.asteron.example',f't13d1517h2_9900{i:08x}_001122334455'),truth_label='malicious',technique='T1505.003',question_tags='persistence,webshell')
        store.add(key=f'exp.persist.{i}.http',activity_id='EASY-PERSIST-001',time=iso(dt+timedelta(milliseconds=70)),host=hq_sensor,source='zeek:http',sourcetype='zeek:http',raw=zeek.http(zts(dt+timedelta(milliseconds=70)),uid,actor,sport,web,443,'POST','portal.asteron.example','/assets/.runtime/status',200,'Mozilla/5.0',resp_len=120+i),truth_label='malicious',technique='T1505.003',question_tags='persistence,webshell')
        store.add(key=f'exp.persist.{i}.waf',activity_id='EASY-PERSIST-001',time=iso(dt+timedelta(milliseconds=75)),host='AWS-WEB-WAF-01',source='aws:waf',sourcetype='aws:waf',raw=apps.waf(iso(dt+timedelta(milliseconds=75)),actor,'portal.asteron.example','/assets/.runtime/status',200,'ALLOW','PublicPortalDefault',f'req-persist-{i:03d}'),truth_label='malicious',technique='T1505.003',question_tags='persistence,webshell')
        _linux_exec(store,key=f'exp.persist.{i}.proc',activity='EASY-PERSIST-001',dt=dt+timedelta(seconds=1),host='USHQ-WEB-02',pid=19300+i,ppid=18422,image='/usr/bin/true',cmd='/usr/bin/true',user='www-data',technique='T1505.003',tags='persistence,webshell')

    # ------------------------------------------------------------------
    # Privilege escalation: evidence of a local privilege transition only;
    # no exploit payload is represented.
    # ------------------------------------------------------------------
    base=at(cfg,0,15,38,0)
    for i in range(8):
        dt=base+timedelta(seconds=i*23)
        _linux_exec(store,key=f'exp.privesc.{i}',activity='EASY-PRIVESC-001',dt=dt,host='USHQ-WEB-02',pid=19500+i,ppid=18422,image='/usr/libexec/asteron-maint-helper',cmd='/usr/libexec/asteron-maint-helper --status',user='root',technique='T1068',tags='privilege_escalation')
        store.add(key=f'exp.privesc.{i}.trellix',activity_id='EASY-PRIVESC-001',time=iso(dt+timedelta(milliseconds=25)),host='USHQ-WEB-02',source='trellix:epo',sourcetype='trellix:epo',raw=apps.trellix_event(iso(dt+timedelta(milliseconds=25)),'USHQ-WEB-02','Unexpected privilege transition from web service context','High','/usr/bin/java','/usr/libexec/asteron-maint-helper','WouldBlock','asteronweb'),truth_label='malicious',technique='T1068',question_tags='privilege_escalation,endpoint_alert')

    # ------------------------------------------------------------------
    # Credential access: inspect deployment configuration and service tokens.
    # ------------------------------------------------------------------
    cred_items=[
        '/srv/asteron-web/config/deploy.env','/etc/asteron/web/deployment.conf','/var/lib/gitlab-runner/config.toml','/srv/asteron-web/.aws/config',
        '/srv/asteron-web/.aws/credentials','/etc/asteron/secrets/app.properties','/srv/asteron-web/config/appsettings.json','/etc/krb5.conf',
        '/etc/asteron/service-accounts.conf','/srv/asteron-web/config/database.yml','/etc/asteron/gitlab/deploy-token','/var/lib/asteron/cache/service-token',
        '/etc/asteron/engineering-sync.conf','/srv/asteron-web/config/backup.properties','/etc/asteron/mft/client.conf','/srv/asteron-web/config/cloud-role.json',
        '/var/lib/asteron/runtime/session.conf','/etc/asteron/monitoring/agent.conf',
    ]
    base=at(cfg,0,15,44,0)
    for i,path in enumerate(cred_items):
        dt=base+timedelta(seconds=i*17); pid=19700+i
        _linux_exec(store,key=f'exp.cred.{i}',activity='EASY-CREDACCESS-001',dt=dt,host='USHQ-WEB-02',pid=pid,ppid=18422,image='/usr/bin/cat',cmd='cat '+path,user='root' if i>=4 else 'www-data',technique='T1552.001',tags='credential_access,configuration')
        store.add(key=f'exp.cred.{i}.file',activity_id='EASY-CREDACCESS-001',time=iso(dt+timedelta(milliseconds=8)),host='USHQ-WEB-02',source='/var/log/syslog',sourcetype='syslog',raw=linux.linux_sysmon_file(syslog_time=syslog_stamp(dt+timedelta(milliseconds=8)),iso_time=iso(dt+timedelta(milliseconds=8)),record_id=store.record_id_at('USHQ-WEB-02','Linux-Sysmon/Operational',dt+timedelta(milliseconds=8)),host='USHQ-WEB-02',guid=uuidg(f'credfile-{i}'),pid=pid,image='/usr/bin/cat',target=path,user='root' if i>=4 else 'www-data'),truth_label='malicious',technique='T1552.001',question_tags='credential_access,configuration')

    # Cloud-side follow-on credential usage and discovery.
    cloud_events=['GetCallerIdentity','ListBuckets','ListObjectsV2','DescribeInstances','DescribeSecurityGroups','DescribeVpcs','DescribeSubnets','ListRoles','ListUsers','GetAccountAuthorizationDetails','DescribeLoadBalancers','ListSecrets','GetParameter','DescribeDBInstances','ListFunctions','ListDistributions','DescribeRepositories','ListObjectsV2','GetObject','GetObject']
    base=at(cfg,0,16,19,0); arn='arn:aws:sts::111122223333:assumed-role/WebPlatformDeployment/svc-webdeploy'
    for i,name in enumerate(cloud_events):
        dt=base+timedelta(seconds=i*12); source='ec2.amazonaws.com' if name.startswith('Describe') else ('s3.amazonaws.com' if name in ('ListBuckets','ListObjectsV2','GetObject') else 'iam.amazonaws.com')
        store.add(key=f'exp.cloud.{i}',activity_id='EASY-CLOUD-DISC-001',time=iso(dt),host='AWS-CLOUDTRAIL-US',source='aws:cloudtrail',sourcetype='aws:cloudtrail',raw=apps.cloudtrail(iso(dt),name,'192.0.2.60',arn,source=source,params={'syntheticContext':'easy-cloud-discovery'}),truth_label='malicious',technique='T1580',question_tags='cloud_discovery,credential_access')
        start=int(dt.timestamp())
        store.add(key=f'exp.cloud.{i}.vpc',activity_id='EASY-CLOUD-DISC-001',time=iso(dt+timedelta(milliseconds=3)),host='AWS-WEB-PROD',source='aws:vpcflow',sourcetype='aws:cloudwatchlogs:vpcflow',raw=apps.aws_vpc_flow(5,'111122223333','eni-0a51b001','10.100.20.15','52.95.245.12',45000+i,443,6,8,2500+i*30,start,start+2),truth_label='malicious',technique='T1580',question_tags='cloud_discovery,network')

    # ------------------------------------------------------------------
    # Discovery: richer Windows and network enumeration on USHQ-APP-07.
    # ------------------------------------------------------------------
    win_cmds=[
        ('whoami /all','T1033'),('hostname','T1082'),('systeminfo','T1082'),('ipconfig /all','T1016'),('route print','T1016'),('arp -a','T1016'),
        ('netstat -ano','T1049'),('tasklist /v','T1057'),('sc query','T1007'),('net user /domain','T1087.002'),('net group /domain','T1069.002'),
        ('net localgroup administrators','T1069.001'),('nltest /domain_trusts','T1482'),('nltest /dclist:us.asteron.local','T1018'),('net view /domain','T1018'),
        (r'net view \\USHQ-FS-03','T1135'),(r'net view \\USVA-FS-01','T1135'),(r'dir \\USHQ-FS-03\Shared','T1083'),(r'dir \\USVA-FS-01\Engineering','T1083'),
        ('wevtutil el','T1654'),('reg query HKLM\\SOFTWARE\\Asteron','T1012'),('wmic computersystem get domain','T1047'),('wmic logicaldisk get name,size,freespace','T1047'),
        ('wmic service get name,state,startmode','T1047'),('quser','T1033'),('query session','T1033'),('set','T1082'),('echo %USERDOMAIN%','T1033'),
        ('net use','T1049'),('net share','T1135'),
    ]
    base=at(cfg,1,15,36,0)
    for i,(cmd,tech) in enumerate(win_cmds):
        dt=base+timedelta(seconds=i*19)
        _win_proc(store,key=f'exp.windisc.{i}',activity='EASY-WIN-DISC-EXPANDED',dt=dt,host='USHQ-APP-07',user=r'US\svc-appdeploy',pid=7600+i,image=r'C:\Windows\System32\cmd.exe',cmd='cmd.exe /c '+cmd,parent=r'C:\Windows\System32\wbem\WmiPrvSE.exe',technique=tech,tags='windows_discovery')
        # Network-correlated discovery for selected commands.
        dst,port,svc=(dc,389,'ldap') if i%4==0 else ((fs,445,'smb') if i%4==1 else ((eng,5985,'http') if i%4==2 else (dns,53,'dns')))
        nt=dt+timedelta(milliseconds=20); uid=zuid(f'windisc-exp-{i}')
        if port==53:
            raw=zeek.dns(zts(nt),uid,app,53200+i,dns,'us.asteron.local',[dc]); src='zeek:dns'; st='zeek:dns'
        else:
            raw=zeek.conn(zts(nt),uid,app,53200+i,dst,port,service=svc,duration=.15,orig_bytes=300+i*5,resp_bytes=700+i*11); src='zeek:conn'; st='zeek:conn'
        store.add(key=f'exp.windisc.{i}.net',activity_id='EASY-WIN-DISC-EXPANDED',time=iso(nt),host=hq_sensor,source=src,sourcetype=st,raw=raw,truth_label='malicious',technique=tech,question_tags='windows_discovery,network')

    # ------------------------------------------------------------------
    # C2 / operator interaction: low-volume TLS sessions to cloud-hosted infra.
    # ------------------------------------------------------------------
    c2_ip=actor
    base=at(cfg,0,16,40,0)
    for i in range(35):
        # Spread through the campaign while remaining inside working/shift noise.
        dt=base+timedelta(minutes=i*115)
        uid=zuid(f'c2-{i}'); sport=55000+i; src_host=web if i<16 else (app if i<27 else eng); sensor=hq_sensor if src_host!=eng else va_sensor
        store.add(key=f'exp.c2.{i}.conn',activity_id='EASY-C2-001',time=iso(dt),host=sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(dt),uid,src_host,sport,c2_ip,443,service='ssl',duration=round(8.2+(i%7)*2.4,2),orig_bytes=1800+i*41,resp_bytes=2400+i*53),truth_label='malicious',technique='T1071.001',question_tags='command_control,network')
        store.add(key=f'exp.c2.{i}.tls',activity_id='EASY-C2-001',time=iso(dt+timedelta(milliseconds=6)),host=sensor,source='zeek:ssl',sourcetype='zeek:ssl',raw=zeek.tls(zts(dt+timedelta(milliseconds=6)),uid,src_host,sport,c2_ip,443,'cloud-edge.example',f't13d1517h2_77{i:010x}_8899aabbccdd'),truth_label='malicious',technique='T1071.001',question_tags='command_control,tls')
        # Endpoint/network corroboration on Windows pivots; Linux on web host.
        if src_host==web:
            store.add(key=f'exp.c2.{i}.linux',activity_id='EASY-C2-001',time=iso(dt+timedelta(milliseconds=10)),host='USHQ-WEB-02',source='/var/log/syslog',sourcetype='syslog',raw=linux.linux_sysmon_network(syslog_time=syslog_stamp(dt+timedelta(milliseconds=10)),iso_time=iso(dt+timedelta(milliseconds=10)),record_id=store.record_id_at('USHQ-WEB-02','Linux-Sysmon/Operational',dt+timedelta(milliseconds=10)),host='USHQ-WEB-02',guid=uuidg(f'c2linux-{i}'),pid=20000+i,image='/usr/bin/curl',src_ip=web,src_port=sport,dst_ip=c2_ip,dst_port=443,user='www-data'),truth_label='malicious',technique='T1071.001',question_tags='command_control,endpoint')
        else:
            whost='USHQ-APP-07' if src_host==app else 'USVA-ENG-APP-01'; user=r'US\svc-appdeploy' if src_host==app else r'US\svc-engsync'
            store.add(key=f'exp.c2.{i}.win',activity_id='EASY-C2-001',time=iso(dt+timedelta(milliseconds=10)),host=whost,source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_network(time=iso(dt+timedelta(milliseconds=10)),record_id=store.record_id_at(whost,'Microsoft-Windows-Sysmon/Operational',dt+timedelta(milliseconds=10)),computer=whost,guid=uuidg(f'c2win-{i}'),pid=str(8800+i),image=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',user=user,src_ip=src_host,src_port=str(sport),dst_ip=c2_ip,dst_port='443',dst_host='cloud-edge.example'),truth_label='malicious',technique='T1071.001',question_tags='command_control,endpoint')
        store.add(key=f'exp.c2.{i}.fw',activity_id='EASY-C2-001',time=iso(dt),host='USHQ-FW-02' if src_host!=eng else 'USVA-FW-02',source='fortigate_traffic',sourcetype='fortigate_traffic',raw=network_devices.fortigate(dt.strftime('%Y-%m-%d'),dt.strftime('%H:%M:%S'),'USHQ-FW-02' if src_host!=eng else 'USVA-FW-02',src_host,c2_ip,sport,443,'accept',330,'server-zone','wan','HTTPS',1800+i*41,2400+i*53),truth_label='malicious',technique='T1071.001',question_tags='command_control,firewall')

    # ------------------------------------------------------------------
    # Lateral movement: repeated authenticated management activity.
    # ------------------------------------------------------------------
    base=at(cfg,2,14,46,0)
    targets=[('USVA-ENG-APP-01',eng,5985,'svc-engsync'),('USVA-FS-01',fs,445,'svc-engsync'),('USHQ-DC-02',dc,135,'svc-appdeploy')]
    for i in range(18):
        thost,dstip,dport,user=targets[i%len(targets)]; dt=base+timedelta(minutes=i*9); sport=56000+i; uid=zuid(f'lateral-{i}')
        store.add(key=f'exp.lat.{i}.4769',activity_id='EASY-LATERAL-001',time=iso(dt-timedelta(seconds=1)),host='USHQ-DC-02',source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=windows.security_4769(time=iso(dt-timedelta(seconds=1)),record_id=store.record_id_at('USHQ-DC-02','Security',dt-timedelta(seconds=1)),computer='USHQ-DC-02',user=user,service=('HTTP/'+thost.lower()+'.us.asteron.local') if dport==5985 else ('cifs/'+thost.lower()+'.us.asteron.local'),client_ip='::ffff:'+app),truth_label='malicious',technique='T1078.002',question_tags='lateral_movement,kerberos')
        store.add(key=f'exp.lat.{i}.conn',activity_id='EASY-LATERAL-001',time=iso(dt),host=hq_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(dt),uid,app,sport,dstip,dport,service='http' if dport==5985 else ('smb' if dport==445 else '-'),duration=2.8,orig_bytes=2800+i*20,resp_bytes=4400+i*30),truth_label='malicious',technique='T1021.006' if dport==5985 else 'T1021.002',question_tags='lateral_movement,network')
        if thost.startswith('USVA'):
            store.add(key=f'exp.lat.{i}.connva',activity_id='EASY-LATERAL-001',time=iso(dt+timedelta(milliseconds=18)),host=va_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(dt+timedelta(milliseconds=18)),uid,app,sport,dstip,dport,service='http' if dport==5985 else 'smb',duration=2.8,orig_bytes=2800+i*20,resp_bytes=4400+i*30,local_orig=False,local_resp=True),truth_label='malicious',technique='T1021.006' if dport==5985 else 'T1021.002',question_tags='lateral_movement,network')
        store.add(key=f'exp.lat.{i}.fw',activity_id='EASY-LATERAL-001',time=iso(dt),host='USHQ-FW-02',source='fortigate_traffic',sourcetype='fortigate_traffic',raw=network_devices.fortigate(dt.strftime('%Y-%m-%d'),dt.strftime('%H:%M:%S'),'USHQ-FW-02',app,dstip,sport,dport,'accept',220,'app-zone','vpn-zone' if thost.startswith('USVA') else 'server-zone','WINRM' if dport==5985 else 'SMB',2800+i*20,4400+i*30),truth_label='malicious',technique='T1021.006' if dport==5985 else 'T1021.002',question_tags='lateral_movement,firewall')
        if thost in ('USVA-ENG-APP-01','USVA-FS-01'):
            store.add(key=f'exp.lat.{i}.4624',activity_id='EASY-LATERAL-001',time=iso(dt+timedelta(seconds=1)),host=thost,source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=windows.security_4624(time=iso(dt+timedelta(seconds=1)),record_id=store.record_id_at(thost,'Security',dt+timedelta(seconds=1)),computer=thost,user=user,domain='US',logon_id=hex(0x90000+i),logon_type=3,ip=app,port=str(sport),auth='Kerberos'),truth_label='malicious',technique='T1078.002',question_tags='lateral_movement,authentication')

    # ------------------------------------------------------------------
    # Collection: multiple items of interest are discovered and accessed.
    # ------------------------------------------------------------------
    files=[
        'regional_engineering_package.pdf','substation_network_overview.pdf','water_treatment_site_layout.xlsx','emergency_operations_contacts.xlsx','vendor_remote_access_matrix.xlsx',
        'power_distribution_maintenance.pdf','engineering_change_calendar.xlsx','network_boundary_diagram.vsdx','pump_station_inventory.xlsx','relay_configuration_reference.xlsx',
        'continuity_contact_roster.xlsx','site_interconnection_matrix.xlsx','engineering_jump_hosts.xlsx','critical_vendor_contacts.xlsx','network_device_inventory.xlsx',
        'facility_access_reference.pdf','operations_support_matrix.xlsx','maintenance_windows.xlsx','regional_asset_inventory.xlsx','engineering_applications.xlsx',
        'field_telemetry_endpoints.xlsx','backup_system_inventory.xlsx','vpn_dependency_matrix.xlsx','site_dns_reference.xlsx','industrial_gateway_inventory.xlsx',
    ]
    base=at(cfg,3,15,25,0)
    for i,name in enumerate(files):
        dt=base+timedelta(seconds=i*31); uid=zuid(f'collect-{i}')
        store.add(key=f'exp.collect.{i}.conn',activity_id='EASY-COLLECT-EXPANDED',time=iso(dt),host=va_sensor,source='zeek:conn',sourcetype='zeek:conn',raw=zeek.conn(zts(dt),uid,eng,57000+i,fs,445,service='smb',duration=3.2,orig_bytes=5000+i*113,resp_bytes=250000+i*8500),truth_label='malicious',technique='T1005',question_tags='collection,network')
        store.add(key=f'exp.collect.{i}.smb',activity_id='EASY-COLLECT-EXPANDED',time=iso(dt+timedelta(milliseconds=7)),host=va_sensor,source='zeek:smb_files',sourcetype='zeek:smb_files',raw=zeek.smb(zts(dt+timedelta(milliseconds=7)),uid,eng,fs,r'\\USVA-FS-01\Engineering\Operations',name),truth_label='malicious',technique='T1005',question_tags='collection,smb')
        store.add(key=f'exp.collect.{i}.file',activity_id='EASY-COLLECT-EXPANDED',time=iso(dt+timedelta(milliseconds=15)),host='USVA-ENG-APP-01',source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_file(time=iso(dt+timedelta(milliseconds=15)),record_id=store.record_id_at('USVA-ENG-APP-01','Microsoft-Windows-Sysmon/Operational',dt+timedelta(milliseconds=15)),computer='USVA-ENG-APP-01',guid=uuidg(f'collectfile-{i}'),pid='6140',image=r'C:\Program Files\Asteron\EngineeringSync\engsync.exe',target=rf'\\USVA-FS-01\Engineering\Operations\{name}'),truth_label='malicious',technique='T1005',question_tags='collection,file')

    # ------------------------------------------------------------------
    # Simple Easy staging: copy selected items to an outbound working folder.
    # Medium/Hard will use more sophisticated archive/multi-host staging.
    # ------------------------------------------------------------------
    base=at(cfg,3,15,52,0)
    stage_files=files[:20]
    for i,name in enumerate(stage_files):
        dt=base+timedelta(seconds=i*18); dst=rf'C:\ProgramData\Asteron\EngineeringSync\outbound\{name}'
        _win_proc(store,key=f'exp.stage.{i}',activity='EASY-STAGE-001',dt=dt,host='USVA-ENG-APP-01',user=r'US\svc-engsync',pid=9200+i,image=r'C:\Windows\System32\cmd.exe',cmd=rf'cmd.exe /c copy "\\USVA-FS-01\Engineering\Operations\{name}" "{dst}"',parent=r'C:\Program Files\Asteron\EngineeringSync\engsync.exe',technique='T1074.001',tags='staging,collection')
        store.add(key=f'exp.stage.{i}.file',activity_id='EASY-STAGE-001',time=iso(dt+timedelta(milliseconds=9)),host='USVA-ENG-APP-01',source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_file(time=iso(dt+timedelta(milliseconds=9)),record_id=store.record_id_at('USVA-ENG-APP-01','Microsoft-Windows-Sysmon/Operational',dt+timedelta(milliseconds=9)),computer='USVA-ENG-APP-01',guid=uuidg(f'stagefile-{i}'),pid=str(9200+i),image=r'C:\Windows\System32\cmd.exe',target=dst),truth_label='malicious',technique='T1074.001',question_tags='staging,file')

    # ------------------------------------------------------------------
    # Exfiltration support evidence around the existing canonical 700 MiB flow.
    # Do not create extra bro:conn records to the answer-bearing destination.
    # ------------------------------------------------------------------
    base=at(cfg,3,16,17,0)
    for i in range(20):
        dt=base+timedelta(seconds=i*7)
        # File-access/queue observations leading up to transfer.
        store.add(key=f'exp.exfilprep.{i}.file',activity_id='EASY-EXFIL-PREP-001',time=iso(dt),host='USVA-ENG-APP-01',source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',raw=windows.sysmon_file(time=iso(dt),record_id=store.record_id_at('USVA-ENG-APP-01','Microsoft-Windows-Sysmon/Operational',dt),computer='USVA-ENG-APP-01',guid=uuidg(f'exfilprep-{i}'),pid='6140',image=r'C:\Program Files\Asteron\EngineeringSync\engsync.exe',target=rf'C:\ProgramData\Asteron\EngineeringSync\outbound\{stage_files[i]}'),truth_label='malicious',technique='T1041',question_tags='exfiltration,staging')
        if i%4==0:
            store.add(key=f'exp.exfilprep.{i}.dlp',activity_id='EASY-EXFIL-PREP-001',time=iso(dt+timedelta(milliseconds=4)),host='USVA-DLP-01',source='dlp:events',sourcetype='dlp:events',raw=apps.dlp(iso(dt+timedelta(milliseconds=4)),r'US\svc-engsync','USVA-ENG-APP-01',stage_files[i],25_000_000+i*1_000_000,cfg['actor_exfil_domain'],'Engineering Sensitive - External Upload','high','alert'),truth_label='malicious',technique='T1041',question_tags='exfiltration,dlp')

    # ------------------------------------------------------------------
    # Defense evasion / cleanup: selective deletion after staging/transfer.
    # ------------------------------------------------------------------
    base=at(cfg,3,16,22,30)
    for i,name in enumerate(stage_files[:15]):
        dt=base+timedelta(seconds=i*14)
        _win_proc(store,key=f'exp.cleanup.{i}',activity='EASY-CLEANUP-001',dt=dt,host='USVA-ENG-APP-01',user=r'US\svc-engsync',pid=9500+i,image=r'C:\Windows\System32\cmd.exe',cmd=rf'cmd.exe /c del "C:\ProgramData\Asteron\EngineeringSync\outbound\{name}"',parent=r'C:\Program Files\Asteron\EngineeringSync\engsync.exe',technique='T1070.004',tags='cleanup,indicator_removal')

