from xml.sax.saxutils import escape
LINUX_GUID='{ff032593-a8d3-4f13-b0d6-01fc615a0f97}'

def linux_sysmon_process(*, syslog_time, iso_time, record_id, host, guid, pid, ppid, image, cmd, user='www-data'):
    fields={'RuleName':'-','UtcTime':iso_time,'ProcessGuid':guid,'ProcessId':pid,'Image':image,'FileVersion':'-','Description':'-','Product':'-','Company':'-',
            'OriginalFileName':'-','CommandLine':cmd,'CurrentDirectory':'/srv/asteron-web/','User':user,'LogonGuid':'{00000000-0000-0000-0000-000000000000}',
            'LogonId':'0','TerminalSessionId':'0','IntegrityLevel':'no level','Hashes':'-','ParentProcessGuid':'{00000000-0000-0000-0000-000000000001}',
            'ParentProcessId':ppid,'ParentImage':'/usr/bin/java','ParentCommandLine':'java -jar /srv/asteron-web/app.jar','ParentUser':'asteronweb'}
    data=''.join(f'<Data Name="{escape(str(k))}">{escape(str(v))}</Data>' for k,v in fields.items())
    xml=(f'<Event><System><Provider Name="Linux-Sysmon" Guid="{LINUX_GUID}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>'
         f'<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="{iso_time}"/><EventRecordID>{record_id}</EventRecordID><Correlation/>'
         f'<Execution ProcessID="{pid}" ThreadID="{pid}"/><Channel>Linux-Sysmon/Operational</Channel><Computer>{host.lower()}.us.asteron.local</Computer><Security UserId="33"/>'
         f'</System><EventData>{data}</EventData></Event>')
    return f'{syslog_time} {host.lower()} sysmon: {xml}'

def audit_exec(*, epoch, serial, host, pid, ppid, uid, exe, cmd):
    args=cmd.split()
    a=' '.join(f'a{i}="{v}"' for i,v in enumerate(args))
    return [
        f'type=SYSCALL msg=audit({epoch}:{serial}): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} auid=4294967295 uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} sgid={uid} fsgid={uid} tty=(none) ses=4294967295 comm="{exe.split("/")[-1]}" exe="{exe}" key="process_exec"',
        f'type=EXECVE msg=audit({epoch}:{serial}): argc={len(args)} {a}',
        f'type=PROCTITLE msg=audit({epoch}:{serial}): proctitle={cmd.encode().hex()}'
    ]

def linux_sysmon_event(*, syslog_time, iso_time, record_id, host, event_id, version, task, fields, pid='1', uid='0'):
    data=''.join(f'<Data Name="{escape(str(k))}">{escape(str(v))}</Data>' for k,v in fields.items())
    xml=(f'<Event><System><Provider Name="Linux-Sysmon" Guid="{LINUX_GUID}"/><EventID>{event_id}</EventID><Version>{version}</Version><Level>4</Level><Task>{task}</Task><Opcode>0</Opcode>'
         f'<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="{iso_time}"/><EventRecordID>{record_id}</EventRecordID><Correlation/>'
         f'<Execution ProcessID="{pid}" ThreadID="{pid}"/><Channel>Linux-Sysmon/Operational</Channel><Computer>{host.lower()}.us.asteron.local</Computer><Security UserId="{uid}"/>'
         f'</System><EventData>{data}</EventData></Event>')
    return f'{syslog_time} {host.lower()} sysmon: {xml}'

def linux_sysmon_file(*, syslog_time, iso_time, record_id, host, guid, pid, image, target, user='www-data'):
    return linux_sysmon_event(syslog_time=syslog_time,iso_time=iso_time,record_id=record_id,host=host,event_id=11,version=2,task=11,pid=str(pid),uid='33',fields={
        'RuleName':'-','UtcTime':iso_time,'ProcessGuid':guid,'ProcessId':pid,'Image':image,'TargetFilename':target,'CreationUtcTime':iso_time,'User':user})

def linux_sysmon_network(*, syslog_time, iso_time, record_id, host, guid, pid, image, src_ip, src_port, dst_ip, dst_port, user='www-data'):
    return linux_sysmon_event(syslog_time=syslog_time,iso_time=iso_time,record_id=record_id,host=host,event_id=3,version=5,task=3,pid=str(pid),uid='33',fields={
        'RuleName':'-','UtcTime':iso_time,'ProcessGuid':guid,'ProcessId':pid,'Image':image,'User':user,'Protocol':'tcp','Initiated':'true','SourceIsIpv6':'false','SourceIp':src_ip,
        'SourceHostname':host.lower()+'.us.asteron.local','SourcePort':src_port,'SourcePortName':'-','DestinationIsIpv6':'false','DestinationIp':dst_ip,'DestinationHostname':'-','DestinationPort':dst_port,'DestinationPortName':'-'})


def linux_sysmon_process_generic(*, syslog_time, iso_time, record_id, host, guid, pid, ppid, image, cmd, user, parent_image, parent_cmd=None, cwd='/'):
    fields={'RuleName':'-','UtcTime':iso_time,'ProcessGuid':guid,'ProcessId':pid,'Image':image,'FileVersion':'-','Description':'-','Product':'-','Company':'-',
            'OriginalFileName':'-','CommandLine':cmd,'CurrentDirectory':cwd,'User':user,'LogonGuid':'{00000000-0000-0000-0000-000000000000}',
            'LogonId':'0','TerminalSessionId':'0','IntegrityLevel':'no level','Hashes':'-','ParentProcessGuid':'{00000000-0000-0000-0000-000000000001}',
            'ParentProcessId':ppid,'ParentImage':parent_image,'ParentCommandLine':parent_cmd or parent_image,'ParentUser':user}
    return linux_sysmon_event(syslog_time=syslog_time,iso_time=iso_time,record_id=record_id,host=host,event_id=1,version=5,task=1,pid=str(pid),uid='0' if user=='root' else '1001',fields=fields)


def secure_auth(ts,host,user,src_ip,result='Accepted',method='publickey',port=22):
    if result == 'Accepted':
        return f'{ts} {host.lower()} sshd[24102]: Accepted {method} for {user} from {src_ip} port {port} ssh2'
    return f'{ts} {host.lower()} sshd[24102]: Failed password for {user} from {src_ip} port {port} ssh2'


def audit_user_auth(*, epoch, serial, host, user, src_ip, pid=24000, uid=0, result='success', exe='/usr/sbin/sshd', terminal='ssh'):
    res='success' if result == 'success' else 'failed'
    return [
        f'type=USER_AUTH msg=audit({epoch}:{serial}): pid={pid} uid={uid} auid={uid} ses={serial%4096} subj=unconfined msg=\'op=PAM:authentication grantors=pam_unix acct="{user}" exe="{exe}" hostname=? addr={src_ip} terminal={terminal} res={res}\'',
        f'type=USER_ACCT msg=audit({epoch}:{serial+1}): pid={pid} uid={uid} auid={uid} ses={serial%4096} subj=unconfined msg=\'op=PAM:accounting grantors=pam_unix acct="{user}" exe="{exe}" hostname=? addr={src_ip} terminal={terminal} res={res}\'',
        f'type=USER_LOGIN msg=audit({epoch}:{serial+2}): pid={pid} uid={uid} auid={uid} ses={serial%4096} subj=unconfined msg=\'op=login id={uid} exe="{exe}" hostname=? addr={src_ip} terminal={terminal} res={res}\'',
        f'type=CRED_ACQ msg=audit({epoch}:{serial+3}): pid={pid} uid={uid} auid={uid} ses={serial%4096} subj=unconfined msg=\'op=PAM:setcred grantors=pam_env,pam_unix acct="{user}" exe="{exe}" hostname=? addr={src_ip} terminal={terminal} res={res}\''
    ]


def audit_account_change(*, epoch, serial, host, admin, target, action='add_user', pid=25000, src_ip='10.45.50.70'):
    type_map={'add_user':'ADD_USER','del_user':'DEL_USER','user_mod':'USER_MGMT','add_group':'ADD_GROUP','group_mod':'GRP_MGMT','passwd':'USER_CHAUTHTOK','cred_change':'CRED_REFR'}
    typ=type_map.get(action,'USER_MGMT')
    op={'add_user':'add-user','del_user':'delete-user','user_mod':'modify-user','add_group':'add-group','group_mod':'modify-group','passwd':'PAM:chauthtok','cred_change':'PAM:setcred'}.get(action,'modify-user')
    exe='/usr/sbin/useradd' if action=='add_user' else '/usr/sbin/usermod'
    return [
        f'type={typ} msg=audit({epoch}:{serial}): pid={pid} uid=0 auid=1001 ses={serial%4096} subj=unconfined msg=\'op={op} acct="{target}" exe="{exe}" hostname=? addr={src_ip} terminal=pts/0 res=success\'',
        f'type=SYSCALL msg=audit({epoch}:{serial+1}): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={pid-1} pid={pid} auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses={serial%4096} comm="{exe.split("/")[-1]}" exe="{exe}" key="identity_change"',
        f'type=PROCTITLE msg=audit({epoch}:{serial+1}): proctitle={(exe+" "+target).encode().hex()}'
    ]
