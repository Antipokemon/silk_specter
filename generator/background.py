from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import json
import random
import uuid

from renderers import windows, linux, zeek, network_devices, apps

DEFAULT_START = datetime(2026, 4, 6, 0, 0, 0, tzinfo=timezone.utc)
DEFAULT_END = datetime(2026, 4, 10, 23, 59, 59, tzinfo=timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def zts(dt):
    return dt.timestamp()


def syslog_stamp(dt):
    return dt.astimezone(timezone.utc).strftime('%b %d %H:%M:%S')


def uuidg(name):
    return '{' + str(uuid.uuid5(uuid.NAMESPACE_DNS, 'asteron:bg:' + name)) + '}'


def zuid(name):
    return 'C' + uuid.uuid5(uuid.NAMESPACE_DNS, 'zeek:bg:' + name).hex[:17]


def _second_octet(site):
    return int(site['cidr'].split('.')[1])


def _ip(site, third, hostnum):
    return f"10.{_second_octet(site)}.{third}.{hostnum}"


def _local_dt(rng, site, profile='business', campaign_start=DEFAULT_START, campaign_end=DEFAULT_END):
    tz = ZoneInfo(site['timezone'])
    while True:
        days=(campaign_end.date()-campaign_start.date()).days+1
        day = rng.randrange(days)
        d = datetime(campaign_start.year, campaign_start.month, campaign_start.day, tzinfo=tz) + timedelta(days=day)
        if profile == 'business':
            minute = rng.randint(6 * 60, 20 * 60)
        elif profile == 'shift':
            minute = rng.randint(0, 24 * 60 - 1)
        elif profile == 'maintenance':
            minute = rng.choice(list(range(0, 6 * 60)) + list(range(20 * 60, 24 * 60)))
        else:
            minute = rng.randint(0, 24 * 60 - 1)
        dt = d + timedelta(minutes=minute, seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))
        utc = dt.astimezone(timezone.utc)
        if campaign_start <= utc <= campaign_end:
            return utc


def _windows_hosts(sites):
    hosts=[]
    for s in sites:
        sec=_second_octet(s)
        # 64 representative endpoints/site in the validation corpus.
        for n in range(1,65):
            hosts.append((f"{s['code']}-WS-{n:04d}", f'10.{sec}.40.{20+n}', s))
        # representative servers / admin systems
        for role,third,start,count in [
            ('APP',30,20,8),('FS',20,20,4),('PAW',50,50,6),('JUMP',50,70,3),('VDI',30,80,3)
        ]:
            for n in range(count):
                hosts.append((f"{s['code']}-{role}-{n+1:02d}",f'10.{sec}.{third}.{start+n}',s))
    return hosts


def _linux_hosts(sites):
    hosts=[]
    for s in sites:
        sec=_second_octet(s)
        for n in range(1,9):
            hosts.append((f"{s['code']}-LNX-{n:02d}",f'10.{sec}.30.{100+n}',s))
    return hosts


def _service_catalog():
    return [
        ('servicenow.asteron.example','10.45.30.42',443,'ssl'),
        ('git.asteron.example','10.100.20.15',443,'ssl'),
        ('atlassian.asteron.example','10.100.30.20',443,'ssl'),
        ('mft.asteron.example','10.45.20.55',443,'ssl'),
        ('wsus.asteron.example','10.44.20.61',8531,'ssl'),
        ('sccm.asteron.example','10.45.20.62',443,'ssl'),
        ('ivanti.asteron.example','10.45.20.63',443,'ssl'),
        ('vdi.asteron.example','10.44.30.80',443,'ssl'),
        ('print.asteron.example','10.44.20.90',445,'smb'),
        ('ai.asteron.example','10.100.40.25',443,'ssl'),
        ('artifacts.asteron.example','10.100.50.25',443,'ssl'),
        ('engineering-data.asteron.example','10.100.60.25',443,'ssl'),
        ('www.microsoft.com','13.107.246.45',443,'ssl'),
        ('login.microsoftonline.com','20.190.128.25',443,'ssl'),
    ]


def _random_user(rng, site_code):
    return f"{site_code[:2]}\\user{rng.randint(100,1299):04d}"


def _wsus_update(rng, host):
    # Updates available before the Apr 6-10, 2026 campaign window.
    # March 2026 cumulative updates remain in normal enterprise rollout during April.
    workstation=[
        ('KB5079473','2026-03 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5079473)'),
        ('KB5077181','2026-02 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5077181)'),
        ('KB2267602','Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'),
        ('KB890830','Windows Malicious Software Removal Tool x64 - v5.142 (KB890830)'),
    ]
    server=[
        ('KB5078766','2026-03 Cumulative Update for Windows Server 2022 for x64-based Systems (KB5078766)'),
        ('KB5075906','2026-02 Cumulative Update for Windows Server 2022 for x64-based Systems (KB5075906)'),
        ('KB2267602','Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'),
    ]
    update_id,title=rng.choice(server if '-APP-' in host or '-FS-' in host or '-VDI-' in host else workstation)
    status=rng.choices(['Installed','Failed','Downloaded','Pending','RebootRequired'],weights=[78,5,7,6,4],k=1)[0]
    return update_id,title,status


def add_enterprise_background(store, count, sites, seed=56018, campaign_start=DEFAULT_START, campaign_end=DEFAULT_END):
    """Add source-diverse, deterministic enterprise background.

    One EventStore event is emitted per requested count so volume is predictable.
    """
    rng=random.Random(seed)
    win_hosts=_windows_hosts(sites)
    lin_hosts=_linux_hosts(sites)
    services=_service_catalog()
    site_by_code={s['code']:s for s in sites}

    categories=[
        ('zeek_conn',16),('zeek_dns',9),('zeek_tls',8),('zeek_http',5),('zeek_smb',2),('zeek_dce',2),
        ('win_auth',10),('win_proc',8),('win_dns',4),('win_change',3),('linux_sysmon',5),('linux_audit',5),('linux_secure',3),
        ('firewall',5),('aws_cloudtrail',3),('aws_vpc',3),('enterprise_app',4),('endpoint',2),('badge',2),('routing_aaa',2),
    ]
    names=[x[0] for x in categories]
    weights=[x[1] for x in categories]

    aws_roles=[
        ('GitLab-Prod','arn:aws:iam::111122223333:role/GitLabRunner','us-east-1'),
        ('WebPlatform-Prod','arn:aws:iam::211122223334:role/WebPlatformRuntime','us-east-1'),
        ('AIPlatform-Dev','arn:aws:iam::311122223335:role/AIResearchDeveloper','us-west-2'),
        ('Atlassian-Prod','arn:aws:iam::411122223336:role/AtlassianApplication','us-east-2'),
        ('EngineeringData-Prod','arn:aws:iam::511122223337:role/EngineeringDataReader','us-east-1'),
        ('Observability-Prod','arn:aws:iam::611122223338:role/ObservabilityCollector','us-west-2'),
    ]

    linux_procs=[
        ('root','/usr/bin/systemctl','systemctl status chronyd','/usr/lib/systemd/systemd'),
        ('splunk','/opt/splunkforwarder/bin/splunkd','splunkd -p 8089 start','/usr/lib/systemd/systemd'),
        ('gitlab-runner','/usr/bin/gitlab-runner','gitlab-runner run --working-directory /var/lib/gitlab-runner','/usr/lib/systemd/systemd'),
        ('svc_monitor','/usr/bin/curl','curl -fsS https://monitor.asteron.example/health','/usr/bin/bash'),
        ('root','/usr/bin/dnf','dnf check-update','/usr/bin/systemd'),
        ('svc_backup','/usr/bin/rsync','rsync -a /srv/data/ backup@backup.asteron.example:/daily/','/usr/bin/bash'),
    ]

    windows_procs=[
        (r'C:\Windows\System32\svchost.exe',r'C:\Windows\System32\svchost.exe -k netsvcs -p',r'C:\Windows\System32\services.exe'),
        (r'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE',r'OUTLOOK.EXE',r'C:\Windows\explorer.exe'),
        (r'C:\Windows\System32\SearchHost.exe',r'SearchHost.exe -ServerName:App.AppX...',r'C:\Windows\System32\svchost.exe'),
        (r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',r'powershell.exe -NoProfile -File C:\ProgramData\Asteron\Inventory.ps1',r'C:\Windows\CCM\CcmExec.exe'),
        (r'C:\Windows\System32\UsoClient.exe',r'UsoClient.exe StartScan',r'C:\Windows\System32\svchost.exe'),
        (r'C:\Program Files\Trellix\Endpoint Security\Platform\ESConfigTool.exe',r'ESConfigTool.exe /status',r'C:\Windows\System32\services.exe'),
    ]

    for i in range(count):
        kind=rng.choices(names,weights=weights,k=1)[0]

        if kind.startswith('zeek_'):
            host,ip,site=rng.choice(win_hosts if rng.random()<0.84 else lin_hosts)
            dt=_local_dt(rng,site,'business' if rng.random()<0.84 else 'shift',campaign_start,campaign_end)
            sensor=f"{site['code']}-ZEEK-01"
            dns_ip=_ip(site,10,20)
            service_name,dst,dport,svc=rng.choice(services)
            uid=zuid(f'{kind}-{i}')
            sport=rng.randint(49152,65530)

            if kind=='zeek_conn':
                store.add(key=f'bg2.conn.{i}',activity_id='BACKGROUND-NETWORK',time=iso(dt),host=sensor,source='zeek:conn',sourcetype='zeek:conn',
                          raw=zeek.conn(zts(dt),uid,ip,sport,dst,dport,service=svc,duration=round(rng.uniform(.02,28),3),orig_bytes=rng.randint(80,25000),resp_bytes=rng.randint(120,220000)),truth_label='background')
            elif kind=='zeek_dns':
                store.add(key=f'bg2.dns.{i}',activity_id='BACKGROUND-NETWORK',time=iso(dt),host=sensor,source='zeek:dns',sourcetype='zeek:dns',
                          raw=zeek.dns(zts(dt),uid,ip,sport,dns_ip,service_name,[dst]),truth_label='background')
            elif kind=='zeek_tls':
                store.add(key=f'bg2.tls.{i}',activity_id='BACKGROUND-NETWORK',time=iso(dt),host=sensor,source='zeek:ssl',sourcetype='zeek:ssl',
                          raw=zeek.tls(zts(dt),uid,ip,sport,dst,dport,service_name,f't13d151{rng.randint(5,8)}h2_{rng.randrange(16**12):012x}_{rng.randrange(16**12):012x}'),truth_label='background')
            elif kind=='zeek_http':
                uri=rng.choice(['/','/health','/api/status','/favicon.ico','/rest/api/2/myself'])
                store.add(key=f'bg2.http.{i}',activity_id='BACKGROUND-NETWORK',time=iso(dt),host=sensor,source='zeek:http',sourcetype='zeek:http',
                          raw=zeek.http(zts(dt),uid,ip,sport,dst,80,'GET',service_name,uri,200,rng.choice(['Mozilla/5.0','Asteron-Monitor/3.4','curl/8.5.0']),resp_len=rng.randint(90,16000)),truth_label='background')
            elif kind=='zeek_smb':
                fs=_ip(site,20,rng.randint(20,39)); name=rng.choice(['department.xlsx','quarterly_report.docx','project_notes.txt','printer_driver.cab'])
                store.add(key=f'bg2.smb.{i}',activity_id='BACKGROUND-NETWORK',time=iso(dt),host=sensor,source='zeek:smb_files',sourcetype='zeek:smb_files',
                          raw=zeek.smb(zts(dt),uid,ip,fs,rf'\\{site["code"]}-FS-01\Shared',name),truth_label='background')
            else:
                server=_ip(site,30,rng.randint(20,29))
                store.add(key=f'bg2.dce.{i}',activity_id='BACKGROUND-NETWORK',time=iso(dt),host=sensor,source='zeek:dce_rpc',sourcetype='zeek:dce_rpc',
                          raw=zeek.dce_rpc(zts(dt),uid,ip,server,endpoint=rng.choice(['svcctl','IWbemLevel1Login','epmapper']),operation=rng.choice(['OpenSCManagerA','NTLMLogin','LookupNames'])),truth_label='background')

        elif kind=='win_auth':
            host,ip,site=rng.choice(win_hosts); dt=_local_dt(rng,site,'business',campaign_start,campaign_end)
            user=_random_user(rng,site['code']); success=rng.random()<0.94
            if success:
                logon_type=rng.choices([2,3,10],[65,28,7],k=1)[0]
                src='-' if logon_type==2 else _ip(site,40,rng.randint(20,180))
                raw=windows.security_4624(time=iso(dt),record_id=store.record_id_at(host,'Security',dt),computer=host,user=user.split('\\')[-1],domain='US',logon_id=hex(rng.randint(0x10000,0xffffff)),logon_type=logon_type,ip=src,port='-' if src=='-' else str(rng.randint(49152,65530)),auth='Kerberos')
                key='4624'
            else:
                src=_ip(site,40,rng.randint(20,180))
                raw=windows.security_4625(time=iso(dt),record_id=store.record_id_at(host,'Security',dt),computer=host,user=user.split('\\')[-1],domain='US',logon_type=3,ip=src,port=str(rng.randint(49152,65530)))
                key='4625'
            store.add(key=f'bg2.{key}.{i}',activity_id='BACKGROUND-WINDOWS-AUTH',time=iso(dt),host=host,source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=raw,truth_label='background')

        elif kind=='win_proc':
            host,ip,site=rng.choice(win_hosts); dt=_local_dt(rng,site,'business',campaign_start,campaign_end)
            image,cmd,parent=rng.choice(windows_procs); user=_random_user(rng,site['code']); guid=uuidg(f'winproc-{i}')
            store.add(key=f'bg2.winproc.{i}',activity_id='BACKGROUND-WINDOWS-PROC',time=iso(dt),host=host,source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',
                      raw=windows.sysmon_process(time=iso(dt),record_id=store.record_id_at(host,'Microsoft-Windows-Sysmon/Operational',dt),computer=host,guid=guid,pid=str(rng.randint(600,18000)),image=image,commandline=cmd,parent_guid=uuidg(f'parent-{i}'),parent_pid=str(rng.randint(400,5500)),parent_image=parent,user=user),truth_label='background')

        elif kind=='win_dns':
            host,ip,site=rng.choice(win_hosts); dt=_local_dt(rng,site,'business',campaign_start,campaign_end); service_name,dst,_,_=rng.choice(services); guid=uuidg(f'windns-{i}')
            store.add(key=f'bg2.windns.{i}',activity_id='BACKGROUND-WINDOWS-DNS',time=iso(dt),host=host,source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',sourcetype='XmlWinEventLog',
                      raw=windows.sysmon_dns(time=iso(dt),record_id=store.record_id_at(host,'Microsoft-Windows-Sysmon/Operational',dt),computer=host,guid=guid,pid=str(rng.randint(1200,15000)),image=r'C:\Windows\System32\svchost.exe',user=_random_user(rng,site['code']),query=service_name,results=f'::ffff:{dst};'),truth_label='background')


        elif kind=='win_change':
            # Native Windows Security account/group change coverage for Splunk_TA_windows.
            dc_choices=[(f"{s['code']}-DC-01",_ip(s,10,11),s) for s in sites]
            host,ip,site=rng.choice(dc_choices); dt=_local_dt(rng,site,'business',campaign_start,campaign_end)
            target=f"user{rng.randint(1300,1999):04d}"; admin=f"adm-idm{rng.randint(1,8):02d}"
            eid=rng.choice([4720,4726,4738,4728,4729,4732,4733])
            kwargs=dict(time=iso(dt),record_id=store.record_id_at(host,'Security',dt),computer=host)
            if eid in (4720,4726,4738):
                raw=getattr(windows,f'security_{eid}')(**kwargs,target_user=target,subject_user=admin,domain='US')
            else:
                group=rng.choice(['Domain Admins','Server Operators','Asteron-App-Admins']) if eid in (4728,4729) else rng.choice(['Administrators','Remote Desktop Users','Backup Operators'])
                raw=getattr(windows,f'security_{eid}')(**kwargs,member_user=target,group_name=group,subject_user=admin,domain='US')
            store.add(key=f'bg2.winchange.{eid}.{i}',activity_id='BACKGROUND-WINDOWS-CHANGE',time=iso(dt),host=host,source='XmlWinEventLog:Security',sourcetype='XmlWinEventLog',raw=raw,truth_label='background')

        elif kind=='linux_sysmon':
            host,ip,site=rng.choice(lin_hosts); dt=_local_dt(rng,site,'shift',campaign_start,campaign_end); user,image,cmd,parent=rng.choice(linux_procs); pid=rng.randint(700,22000)
            store.add(key=f'bg2.linuxsysmon.{i}',activity_id='BACKGROUND-LINUX',time=iso(dt),host=host,source='/var/log/syslog',sourcetype='syslog',
                      raw=linux.linux_sysmon_process_generic(syslog_time=syslog_stamp(dt),iso_time=iso(dt),record_id=store.record_id_at(host,'Linux-Sysmon/Operational',dt),host=host,guid=uuidg(f'linuxproc-{i}'),pid=pid,ppid=rng.randint(1,4000),image=image,cmd=cmd,user=user,parent_image=parent),truth_label='background')

        elif kind=='linux_audit':
            host,ip,site=rng.choice(lin_hosts); dt=_local_dt(rng,site,'shift',campaign_start,campaign_end); user,image,cmd,parent=rng.choice(linux_procs); pid=rng.randint(700,22000)
            mode=rng.random()
            if mode < 0.45:
                bundle=linux.audit_exec(epoch=int(dt.timestamp()),serial=900000+i*10,host=host,pid=pid,ppid=rng.randint(1,4000),uid=0 if user=='root' else 1001,exe=image,cmd=cmd)
            elif mode < 0.78:
                auth_user=rng.choice(['sysadmin','svc_backup','svc_monitor','ansible'])
                bundle=linux.audit_user_auth(epoch=int(dt.timestamp()),serial=900000+i*10,host=host,user=auth_user,src_ip=_ip(site,50,rng.randint(50,90)),pid=pid,uid=1001,result='success' if rng.random()<0.9 else 'failed')
            else:
                action=rng.choice(['add_user','del_user','user_mod','add_group','group_mod','passwd','cred_change'])
                bundle=linux.audit_account_change(epoch=int(dt.timestamp()),serial=900000+i*10,host=host,admin='sysadmin',target=rng.choice(['svc_batch','opsmaint','engsupport','wheel']),action=action,pid=pid,src_ip=_ip(site,50,rng.randint(50,90)))
            for j,line in enumerate(bundle):
                store.add(key=f'bg2.linuxaudit.{i}.{j}',activity_id='BACKGROUND-LINUX',time=iso(dt+timedelta(milliseconds=j)),host=host,source='/var/log/audit/audit.log',sourcetype='linux_audit',raw=line,truth_label='background')

        elif kind=='linux_secure':
            host,ip,site=rng.choice(lin_hosts); dt=_local_dt(rng,site,'shift',campaign_start,campaign_end); src=_ip(site,50,rng.randint(50,90)); user=rng.choice(['svc_backup','svc_monitor','sysadmin','ansible']); success=rng.random()<0.93
            store.add(key=f'bg2.linuxsecure.{i}',activity_id='BACKGROUND-LINUX-AUTH',time=iso(dt),host=host,source='/var/log/secure',sourcetype='linux_secure',
                      raw=linux.secure_auth(syslog_stamp(dt),host,user,src,'Accepted' if success else 'Failed',method='publickey' if success else 'password',port=rng.randint(49152,65530)),truth_label='background')

        elif kind=='firewall':
            host,ip,site=rng.choice(win_hosts if rng.random()<0.8 else lin_hosts); dt=_local_dt(rng,site,'shift',campaign_start,campaign_end); service_name,dst,dport,_=rng.choice(services); sport=rng.randint(49152,65530); vendor=rng.randrange(3)
            if vendor==0:
                fw=f"{site['code']}-FW-01"; st='pan:traffic'; raw=network_devices.palo_alto(dt.strftime('%Y/%m/%d %H:%M:%S'),'PA-'+site['code']+'-001',ip,dst,sport,dport,'allow','STANDARD-EGRESS','users','untrust',bytes_out=rng.randint(80,30000),bytes_in=rng.randint(100,300000))
            elif vendor==1:
                fw=f"{site['code']}-FW-02"; st='fortigate_traffic'; raw=network_devices.fortigate(dt.strftime('%Y-%m-%d'),dt.strftime('%H:%M:%S'),fw,ip,dst,sport,dport,'accept',rng.randint(100,400),'lan','wan','HTTPS',rng.randint(80,30000),rng.randint(100,300000))
            else:
                fw=f"{site['code']}-FW-03"; st='cisco:asa'; raw=network_devices.cisco_asa(dt.strftime('%b %d %Y %H:%M:%S'),fw,'302013',ip,sport,dst,dport)
            store.add(key=f'bg2.fw.{i}',activity_id='BACKGROUND-FIREWALL',time=iso(dt),host=fw,source=st,sourcetype=st,raw=raw,truth_label='background')

        elif kind=='aws_cloudtrail':
            account_name,arn,region=rng.choice(aws_roles); dt=_local_dt(rng,rng.choice(sites),'shift',campaign_start,campaign_end); event=rng.choice([
                'AssumeRole','GetCallerIdentity','DescribeInstances','DescribeSecurityGroups','DescribeSubnets','DescribeVpcs',
                'ListBuckets','GetObject','ListObjectsV2','DescribeLogGroups','GetSecretValue','ListSecrets','GetParameter',
                'DescribeDBInstances','DescribeLoadBalancers','DescribeRepositories','ListFunctions','ListDistributions','ListRoles','ListUsers'])
            src=rng.choice(['10.100.10.'+str(rng.randint(20,80)),'52.95.245.'+str(rng.randint(1,240))])
            store.add(key=f'bg2.awsct.{i}',activity_id='BACKGROUND-AWS',time=iso(dt),host=f'AWS-{account_name.upper()}',source='aws:cloudtrail',sourcetype='aws:cloudtrail',
                      raw=apps.cloudtrail(iso(dt),event,src,arn,region=region,user_agent=rng.choice(['aws-cli/2.15.0','Boto3/1.34.0 Python/3.12','aws-sdk-java/2.25'])),truth_label='background')

        elif kind=='aws_vpc':
            account_name,arn,region=rng.choice(aws_roles); dt=_local_dt(rng,rng.choice(sites),'shift',campaign_start,campaign_end); src=f'10.100.{rng.randint(10,89)}.{rng.randint(10,240)}'; dst=rng.choice(['10.44.20.31','10.45.30.42','52.95.245.12','13.107.246.45']); sport=rng.randint(49152,65530); dport=rng.choice([443,22,5432,3389]); start=int(dt.timestamp()); end=start+rng.randint(1,120)
            store.add(key=f'bg2.awsvpc.{i}',activity_id='BACKGROUND-AWS-NETWORK',time=iso(dt),host=f'AWS-{account_name.upper()}',source='aws:vpcflow',sourcetype='aws:cloudwatchlogs:vpcflow',
                      raw=apps.aws_vpc_flow(5,'111122223333','eni-0'+f'{rng.randrange(16**8):08x}',src,dst,sport,dport,6,rng.randint(2,100),rng.randint(500,900000),start,end),truth_label='background')

        elif kind=='enterprise_app':
            site=rng.choice(sites); dt=_local_dt(rng,site,'business',campaign_start,campaign_end); user=_random_user(rng,site['code']); host,ip,_=rng.choice(win_hosts); subtype=rng.randrange(9)
            if subtype==0:
                st='servicenow:audit'; h='SAAS-SERVICENOW'; raw=apps.servicenow_audit(iso(dt),user,'update',rng.choice(['incident','change_request','sc_task']),f'CHG{rng.randint(1000000,9999999)}',ip,'routine service workflow')
            elif subtype==1:
                st='tenable:io:vuln'; h='USNO-TEN-01'; target,tip,tsite=rng.choice(win_hosts+lin_hosts); raw=apps.tenable_vuln(iso(dt),'10.45.50.31',tip,target,rng.randint(10000,99999),rng.choice(['SSL Certificate Information','Service Detection','Operating System Identification','SMB Security Mode']),rng.choice(['info','low','medium']),rng.choice([22,80,443,445,3389]))
            elif subtype==2:
                st='sccm:client'; h=host; raw=apps.sccm_event(iso(dt),site['code'],host,user,rng.choice(['hardware_inventory','application_deployment','policy_request']),'success')
            elif subtype==3:
                st='wsus:client'; h=host; update_id,title,status=_wsus_update(rng,host); raw=apps.wsus_event(iso(dt),host,update_id,title,status)
            elif subtype==4:
                st='ivanti:events'; h='USNO-IVANTI-01'; action=rng.choice(['patch_install','update_deploy','package_install','software_distribution']); result=rng.choice(['success','success','success','failed']); raw=apps.ivanti_event(iso(dt),host,user,action,result,job='Patch and Compliance',update_id='IV-'+str(rng.randint(100000,999999)),package_name=rng.choice(['Windows Monthly Quality Update','Trellix ENS Content Update','Asteron Engineering Client']),version=rng.choice(['2026.04','2026.04.1','10.7.0.2214']),file_name=rng.choice(['windows11.0-kb5071123-x64.msu','amcore-2026.04.10.dat','asteron-eng-client-6.4.2.msi']))
            elif subtype==5:
                st='vdi:session'; h='USHQ-VDI-01'; raw=apps.vdi_session(iso(dt),user,host,'Asteron-Standard-Desktop',rng.choice(['logon','reconnect','logoff']))
            elif subtype==6:
                st='mft:transfer'; h='USNO-MFT-01'; raw=apps.mft_transfer(iso(dt),user,host,rng.choice(['daily_export.csv','vendor_patch.zip','billing_extract.csv']),rng.randint(50000,80000000),rng.choice(['partner-a.example','partner-b.example','gov-exchange.example']),'upload','success',f'tx-{i:08d}')
            elif subtype==7:
                st='gitlab:audit'; h='AWS-GITLAB-01'; raw=apps.gitlab_audit(iso(dt),user.split('\\')[-1],ip,'Project',rng.choice(['repository_download','push','pipeline_created','merge_request_created']),rng.choice(['asteron/web-platform','asteron/infrastructure','asteron/engineering-api']),{'auth_method':'sso'})
            else:
                st='print:events'; h='USHQ-PRINT-01'; raw=apps.print_event(iso(dt),user,host,'USHQ-PRN-'+str(rng.randint(1,40)),rng.choice(['work_order.pdf','budget.xlsx','engineering_change.pdf']),rng.randint(1,45))
            store.add(key=f'bg2.app.{i}',activity_id='BACKGROUND-ENTERPRISE-APP',time=iso(dt),host=h,source=st,sourcetype=st,raw=raw,truth_label='background')

        elif kind=='endpoint':
            host,ip,site=rng.choice(win_hosts+lin_hosts); dt=_local_dt(rng,site,'shift',campaign_start,campaign_end); use_defender=rng.random()<0.62
            if use_defender:
                st='ms:defender:eventhub'; raw=apps.defender_event(iso(dt),host,rng.choice(['Potentially unwanted application blocked','Suspicious script behavior reviewed','Network protection allowed enterprise service']),rng.choice(['Informational','Low']),_random_user(rng,site['code']),'explorer.exe','powershell.exe',rng.choice(['AlertResolved','BehaviorObserved']))
            else:
                st='trellix:epo'; raw=apps.trellix_event(iso(dt),host,rng.choice(['On-access scan completed','Potentially unwanted program detected','Exploit prevention rule observed']),rng.choice(['Informational','Low']),'explorer.exe','',rng.choice(['Allowed','Blocked','WouldBlock']),_random_user(rng,site['code']))
            store.add(key=f'bg2.endpoint.{i}',activity_id='BACKGROUND-ENDPOINT-SECURITY',time=iso(dt),host=host,source=st,sourcetype=st,raw=raw,truth_label='background')

        elif kind=='badge':
            site=rng.choice(sites); dt=_local_dt(rng,site,'business',campaign_start,campaign_end); emp=rng.randint(100000,199999); result='GRANTED' if rng.random()<0.985 else 'DENIED'
            store.add(key=f'bg2.badge.{i}',activity_id='BACKGROUND-PHYSICAL',time=iso(dt),host=site['code']+'-PACS-01',source='pacs:access',sourcetype='pacs:access',raw=apps.badge(iso(dt),'B-'+str(emp),'E'+str(emp),site['code'],site['code']+'-ENTRY-'+str(rng.randint(1,12)),result),truth_label='background')

        else:  # routing_aaa
            site=rng.choice(sites); dt=_local_dt(rng,site,'shift',campaign_start,campaign_end); subtype=rng.choices(range(8),weights=[10,12,3,8,10,14,3,14],k=1)[0]
            mgmt_ip=_ip(site,50,rng.randint(50,90)); user='adm-net'+str(rng.randint(1,20))
            if subtype==0:
                h=site['code']+'-RTR-01'; st='cisco:ios'; raw=network_devices.cisco_ios(syslog_stamp(dt),h,'OSPF-5-ADJCHG',f'Process 100, Nbr 10.{_second_octet(site)}.2.2 on Tunnel10 from FULL to FULL, adjacency refreshed')
            elif subtype==1:
                h=site['code']+'-RTR-01'; st='cisco:ios'; raw=network_devices.cisco_ios_login(syslog_stamp(dt),h,user,mgmt_ip,success=True)
            elif subtype==2:
                h=site['code']+'-RTR-01'; st='cisco:ios'; raw=network_devices.cisco_ios_login(syslog_stamp(dt),h,user,mgmt_ip,success=False)
            elif subtype==3:
                h=site['code']+'-RTR-01'; st='cisco:ios'; raw=network_devices.cisco_ios_config(syslog_stamp(dt),h,user,mgmt_ip)
            elif subtype==4:
                h=site['code']+'-RTR-02'; st='juniper:junos:firewall'; raw=network_devices.junos_syslog(syslog_stamp(dt),h,'rpd',f'RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 198.18.{_second_octet(site)}.1 changed state from OpenConfirm to Established')
            elif subtype==5:
                h=site['code']+'-RTR-02'; st='juniper'; raw=network_devices.junos_login(syslog_stamp(dt),h,user,mgmt_ip,_ip(site,2,12),success=True,src_port=rng.randint(49152,65530))
            elif subtype==6:
                h=site['code']+'-RTR-02'; st='juniper'; raw=network_devices.junos_login(syslog_stamp(dt),h,user,mgmt_ip,_ip(site,2,12),success=False,src_port=rng.randint(49152,65530))
            else:
                h='USNO-TACACS-01' if rng.random()<0.5 else 'USNO-RADIUS-01'
                if h.endswith('TACACS-01'):
                    st='tacacs'
                    tac_result=rng.choices(['PASS','FAIL'],weights=[86,14],k=1)[0]
                    tac_reason='' if tac_result=='PASS' else rng.choice(['invalid credentials','unauthorized administrative user','denied shell access','authorization failure'])
                    raw=apps.tacacs_auth(iso(dt),h,user,site['code']+'-FW-01',mgmt_ip,result=tac_result,reason=tac_reason)
                else:
                    st='radius'; raw=apps.radius_auth(iso(dt),h,_random_user(rng,site['code']),site['code']+'-VPN-01',_ip(site,40,rng.randint(20,180)),method=rng.choice(['EAP-TLS','MSCHAPv2']))
            store.add(key=f'bg2.routeaaa.{i}',activity_id='BACKGROUND-NETWORK-MGMT',time=iso(dt),host=h,source=st,sourcetype=st,raw=raw,truth_label='background')


def add_defender_detection_background(store, sites, alert_count=180, seed=56029, campaign_start=DEFAULT_START, campaign_end=DEFAULT_END):
    """Add paired Defender AlertInfo/AlertEvidence Event Hub records."""
    rng=random.Random(seed)
    win_hosts=_windows_hosts(sites)
    detections=[
        ('PUA:Win32/RemoteAdminTool','Low','Malware','RemoteAdminTool','Quarantine','Remediated','remote-admin.exe',r'C:\Users\Public',r'remote-admin.exe /service'),
        ('Behavior:Win32/SuspiciousPowerShell.A','Medium','Execution','SuspiciousPowerShell','Block','Remediated','powershell.exe',r'C:\Windows\System32\WindowsPowerShell\v1.0',r'powershell.exe -NoProfile -File C:\ProgramData\Asteron\Inventory.ps1'),
        ('Trojan:Win32/Emotet.Synthetic','High','Malware','Emotet','Quarantine','Remediated','invoice_viewer.exe',r'C:\Users\Public\Downloads',r'"C:\Users\Public\Downloads\invoice_viewer.exe"'),
        ('Behavior:Win32/CredentialAccess.Synthetic','Medium','CredentialAccess','CredentialAccess','Block','PartiallyRemediated','rundll32.exe',r'C:\Windows\System32',r'rundll32.exe benign-training.dll,EntryPoint'),
        ('PUA:Win32/UnsignedUtility','Low','Malware','UnsignedUtility','Allow','Active','support-tool.exe',r'C:\Program Files\Asteron\Support',r'support-tool.exe --inventory'),
    ]
    for i in range(alert_count):
        host,ip,site=rng.choice(win_hosts)
        dt=_local_dt(rng,site,'shift',campaign_start,campaign_end)
        title,severity,category,family,rem_action,rem_status,file_name,folder,cmd=rng.choice(detections)
        user=_random_user(rng,site['code'])
        alert_id='da'+uuid.uuid5(uuid.NAMESPACE_DNS,f'asteron:defender:{i}').hex[:30]
        store.add(key=f'bg2.defalert.info.{i}',activity_id='BACKGROUND-DEFENDER-DETECTION',time=iso(dt),host=host,source='ms:defender:eventhub',sourcetype='ms:defender:eventhub',
                  raw=apps.defender_alert_info(iso(dt),alert_id,title,severity,category,attack_techniques=''),truth_label='background')
        store.add(key=f'bg2.defalert.evidence.{i}',activity_id='BACKGROUND-DEFENDER-DETECTION',time=iso(dt+timedelta(milliseconds=8)),host=host,source='ms:defender:eventhub',sourcetype='ms:defender:eventhub',
                  raw=apps.defender_alert_evidence(iso(dt+timedelta(milliseconds=8)),alert_id,title,severity,host,user,file_name,folder,cmd,family,
                                                   detection_category=category,remediation_status=rem_status,remediation_action=rem_action),truth_label='background')
