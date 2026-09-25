from xml.sax.saxutils import escape

SEC_GUID='{54849625-5478-4994-a5ba-3e3b0328c30d}'
SYSMON_GUID='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'

def _data(fields):
    return ''.join(f"<Data Name='{escape(str(k), {chr(39): '&apos;'})}'>{escape(str(v))}</Data>" for k,v in fields.items())

def win_event(*, event_id, version, level, task, keywords, time, record_id, computer, execution_pid, execution_tid, fields):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{SEC_GUID}"/><EventID>{event_id}</EventID>'
            f'<Version>{version}</Version><Level>{level}</Level><Task>{task}</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>'
            f'<TimeCreated SystemTime="{time}"/><EventRecordID>{record_id}</EventRecordID><Correlation/>'
            f'<Execution ProcessID="{execution_pid}" ThreadID="{execution_tid}"/><Channel>Security</Channel>'
            f'<Computer>{escape(computer)}.us.asteron.local</Computer><Security/></System><EventData>{_data(fields)}</EventData></Event>')

def security_4624(*, time, record_id, computer, user, domain='US', logon_id='0x3e7', logon_type=3, ip='-', port='-', process='-', auth='Kerberos'):
    fields={
        'SubjectUserSid':'S-1-5-18','SubjectUserName':computer+'$','SubjectDomainName':domain,'SubjectLogonId':'0x3e7',
        'TargetUserSid':'S-1-5-21-104481-204842-304113-1108','TargetUserName':user,'TargetDomainName':domain,'TargetLogonId':logon_id,
        'LogonType':logon_type,'LogonProcessName':'NtLmSsp' if auth=='NTLM' else 'Kerberos','AuthenticationPackageName':auth,
        'WorkstationName':'-','LogonGuid':'{00000000-0000-0000-0000-000000000000}','TransmittedServices':'-','LmPackageName':'-',
        'KeyLength':'0','ProcessId':'0x0','ProcessName':process,'IpAddress':ip,'IpPort':port,'ImpersonationLevel':'%%1833'
    }
    return win_event(event_id=4624,version=2,level=0,task=12544,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=736,execution_tid=940,fields=fields)

def security_4688(*, time, record_id, computer, subject_user, new_pid_hex, image, parent, commandline, logon_id='0x3e7'):
    fields={
        'SubjectUserSid':'S-1-5-21-104481-204842-304113-1108','SubjectUserName':subject_user,'SubjectDomainName':'US','SubjectLogonId':logon_id,
        'NewProcessId':new_pid_hex,'NewProcessName':image,'TokenElevationType':'%%1936','ProcessId':'0x0f20','CommandLine':commandline,
        'TargetUserSid':'S-1-0-0','TargetUserName':'-','TargetDomainName':'-','TargetLogonId':'0x0','ParentProcessName':parent,'MandatoryLabel':'S-1-16-8192'
    }
    return win_event(event_id=4688,version=2,level=0,task=13312,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=4,execution_tid=4732,fields=fields)

def sysmon_event(*, event_id, version, task, time, record_id, computer, fields, process_id='3260', thread_id='4072'):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="Microsoft-Windows-Sysmon" Guid="{SYSMON_GUID}"/><EventID>{event_id}</EventID><Version>{version}</Version>'
            f'<Level>4</Level><Task>{task}</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>'
            f'<TimeCreated SystemTime="{time}"/><EventRecordID>{record_id}</EventRecordID><Correlation/>'
            f'<Execution ProcessID="{process_id}" ThreadID="{thread_id}"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
            f'<Computer>{escape(computer)}.us.asteron.local</Computer><Security UserID="S-1-5-18"/></System><EventData>{_data(fields)}</EventData></Event>')

def sysmon_process(*, time, record_id, computer, guid, pid, image, commandline, parent_guid, parent_pid, parent_image, user, hashes='SHA256=2D711642B726B04401627CA9FBAC32F5C8530FB1903CC4DB02258717921A4881'):
    return sysmon_event(event_id=1,version=5,task=1,time=time,record_id=record_id,computer=computer,fields={
        'RuleName':'-','UtcTime':time,'ProcessGuid':guid,'ProcessId':pid,'Image':image,'FileVersion':'10.0.26100.1','Description':'-','Product':'Microsoft Windows Operating System',
        'Company':'Microsoft Corporation','OriginalFileName':image.split('\\')[-1],'CommandLine':commandline,'CurrentDirectory':'C:\\Windows\\System32\\',
        'User':user,'LogonGuid':'{b03d4f38-1f5a-67ea-8a91-060000000000}','LogonId':'0x6a91f','TerminalSessionId':'0','IntegrityLevel':'High','Hashes':hashes,
        'ParentProcessGuid':parent_guid,'ParentProcessId':parent_pid,'ParentImage':parent_image,'ParentCommandLine':parent_image,'ParentUser':user})

def sysmon_network(*, time, record_id, computer, guid, pid, image, user, src_ip, src_port, dst_ip, dst_port, dst_host='-', protocol='tcp'):
    return sysmon_event(event_id=3,version=5,task=3,time=time,record_id=record_id,computer=computer,fields={
        'RuleName':'-','UtcTime':time,'ProcessGuid':guid,'ProcessId':pid,'Image':image,'User':user,'Protocol':protocol,'Initiated':'true','SourceIsIpv6':'false',
        'SourceIp':src_ip,'SourceHostname':computer.lower()+'.us.asteron.local','SourcePort':src_port,'SourcePortName':'-',
        'DestinationIsIpv6':'false','DestinationIp':dst_ip,'DestinationHostname':dst_host,'DestinationPort':dst_port,'DestinationPortName':'-'})

def sysmon_file(*, time, record_id, computer, guid, pid, image, target):
    return sysmon_event(event_id=11,version=2,task=11,time=time,record_id=record_id,computer=computer,fields={
        'RuleName':'-','UtcTime':time,'ProcessGuid':guid,'ProcessId':pid,'Image':image,'TargetFilename':target,'CreationUtcTime':time,'User':'US\\svc-engsync'})


def security_4625(*, time, record_id, computer, user, domain='US', logon_type=3, ip='-', port='-', status='0xC000006D', substatus='0xC000006A'):
    fields={
        'SubjectUserSid':'S-1-0-0','SubjectUserName':'-','SubjectDomainName':'-','SubjectLogonId':'0x0',
        'TargetUserSid':'S-1-0-0','TargetUserName':user,'TargetDomainName':domain,'Status':status,'FailureReason':'%%2313','SubStatus':substatus,
        'LogonType':logon_type,'LogonProcessName':'NtLmSsp','AuthenticationPackageName':'NTLM','WorkstationName':'-',
        'TransmittedServices':'-','LmPackageName':'-','KeyLength':'0','ProcessId':'0x0','ProcessName':'-','IpAddress':ip,'IpPort':port
    }
    return win_event(event_id=4625,version=0,level=0,task=12544,keywords='0x8010000000000000',time=time,record_id=record_id,computer=computer,execution_pid=736,execution_tid=940,fields=fields)


def security_4672(*, time, record_id, computer, user, domain='US', logon_id='0x3e7'):
    fields={'SubjectUserSid':'S-1-5-21-104481-204842-304113-1108','SubjectUserName':user,'SubjectDomainName':domain,'SubjectLogonId':logon_id,
            'PrivilegeList':'SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeImpersonatePrivilege'}
    return win_event(event_id=4672,version=0,level=0,task=12548,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=736,execution_tid=940,fields=fields)


def security_4768(*, time, record_id, computer, user, domain='US.ASTERON.LOCAL', client_ip='::ffff:10.44.40.25', cert=False, result='0x0'):
    fields={'TargetUserName':user,'TargetDomainName':domain,'TargetSid':'S-1-5-21-104481-204842-304113-1108','ServiceName':'krbtgt','ServiceSid':'S-1-5-21-104481-204842-304113-502',
            'TicketOptions':'0x40810010','Status':result,'TicketEncryptionType':'0x12','PreAuthType':'16' if cert else '2','IpAddress':client_ip,'IpPort':'55122',
            'CertIssuerName':'CN=Asteron Enterprise CA,DC=asteron,DC=local' if cert else '', 'CertSerialNumber':'4A7700A1001' if cert else '', 'CertThumbprint':'A1B2C3D4E5F6' if cert else ''}
    return win_event(event_id=4768,version=2,level=0,task=14339,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=752,execution_tid=2180,fields=fields)


def security_4769(*, time, record_id, computer, user, service, client_ip='::ffff:10.44.40.25', ticket_encryption='0x12', status='0x0'):
    fields={'TargetUserName':user,'TargetDomainName':'US.ASTERON.LOCAL','ServiceName':service,'ServiceSid':'S-1-5-21-104481-204842-304113-1109','TicketOptions':'0x40810000',
            'TicketEncryptionType':ticket_encryption,'IpAddress':client_ip,'IpPort':'55123','Status':status,'LogonGuid':'{00000000-0000-0000-0000-000000000000}','TransmittedServices':'-'}
    return win_event(event_id=4769,version=2,level=0,task=14337,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=752,execution_tid=2180,fields=fields)


def sysmon_dns(*, time, record_id, computer, guid, pid, image, user, query, results=''):
    return sysmon_event(event_id=22,version=5,task=22,time=time,record_id=record_id,computer=computer,fields={
        'RuleName':'-','UtcTime':time,'ProcessGuid':guid,'ProcessId':pid,'QueryName':query,'QueryStatus':'0','QueryResults':results,'Image':image,'User':user})


def _change_subject(subject_user='adm-idm01', domain='US', logon_id='0x7a4d2'):
    return {
        'SubjectUserSid':'S-1-5-21-104481-204842-304113-1120',
        'SubjectUserName':subject_user,
        'SubjectDomainName':domain,
        'SubjectLogonId':logon_id,
    }


def security_4720(*, time, record_id, computer, target_user, subject_user='adm-idm01', domain='US'):
    fields={**_change_subject(subject_user,domain),
        'TargetUserName':target_user,'TargetDomainName':domain,
        'TargetSid':'S-1-5-21-104481-204842-304113-2201','SamAccountName':target_user,
        'DisplayName':target_user.replace('.',' ').title(),'UserPrincipalName':f'{target_user}@us.asteron.local',
        'HomeDirectory':'-','HomePath':'-','ScriptPath':'-','ProfilePath':'-','UserWorkstations':'-',
        'PasswordLastSet':'%%1794','AccountExpires':'%%1794','PrimaryGroupId':'513','AllowedToDelegateTo':'-',
        'OldUacValue':'0x0','NewUacValue':'0x15','UserAccountControl':'%%2080\n\t\t%%2082\n\t\t%%2084',
        'UserParameters':'-','SidHistory':'-','LogonHours':'%%1793'}
    return win_event(event_id=4720,version=0,level=0,task=13824,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=688,execution_tid=2112,fields=fields)


def security_4726(*, time, record_id, computer, target_user, subject_user='adm-idm01', domain='US'):
    fields={**_change_subject(subject_user,domain),'TargetUserName':target_user,'TargetDomainName':domain,'TargetSid':'S-1-5-21-104481-204842-304113-2201'}
    return win_event(event_id=4726,version=0,level=0,task=13824,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=688,execution_tid=2112,fields=fields)


def security_4738(*, time, record_id, computer, target_user, subject_user='adm-idm01', domain='US'):
    fields={**_change_subject(subject_user,domain),'TargetUserName':target_user,'TargetDomainName':domain,'TargetSid':'S-1-5-21-104481-204842-304113-2201',
        'SamAccountName':target_user,'DisplayName':target_user.replace('.',' ').title(),'UserPrincipalName':f'{target_user}@us.asteron.local',
        'HomeDirectory':'-','HomePath':'-','ScriptPath':'-','ProfilePath':'-','UserWorkstations':'-','PasswordLastSet':'%%1793','AccountExpires':'%%1793',
        'PrimaryGroupId':'513','AllowedToDelegateTo':'-','OldUacValue':'0x15','NewUacValue':'0x15','UserAccountControl':'-','UserParameters':'-','SidHistory':'-','LogonHours':'%%1793'}
    return win_event(event_id=4738,version=0,level=0,task=13824,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=688,execution_tid=2112,fields=fields)


def _group_change(event_id, *, time, record_id, computer, member_user, group_name, subject_user='adm-idm01', domain='US', local=False):
    fields={**_change_subject(subject_user,domain),
        'MemberName':f'CN={member_user},OU=Users,DC=us,DC=asteron,DC=local',
        'MemberId':'S-1-5-21-104481-204842-304113-2201',
        'TargetUserName':group_name,'TargetDomainName':domain,
        'TargetSid':'S-1-5-21-104481-204842-304113-'+('544' if local else '512')}
    return win_event(event_id=event_id,version=0,level=0,task=13826 if local else 13826,keywords='0x8020000000000000',time=time,record_id=record_id,computer=computer,execution_pid=688,execution_tid=2112,fields=fields)


def security_4728(**kwargs): return _group_change(4728,local=False,**kwargs)
def security_4729(**kwargs): return _group_change(4729,local=False,**kwargs)
def security_4732(**kwargs): return _group_change(4732,local=True,**kwargs)
def security_4733(**kwargs): return _group_change(4733,local=True,**kwargs)
