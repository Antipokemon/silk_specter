import json
import hashlib


def _event_defaults(event_name, region, account, ordinal='001'):
    suffix=str(ordinal).zfill(3)
    arn=f'arn:aws:iam::{account}:role/AsteronSyntheticRole'
    table={
        'AssumeRole': ('sts.amazonaws.com', {'roleArn':arn,'roleSessionName':f'asteron-session-{suffix}','durationSeconds':3600}, {'assumedRoleUser':{'assumedRoleId':f'AROASYNTH:{suffix}','arn':f'arn:aws:sts::{account}:assumed-role/AsteronSyntheticRole/asteron-session-{suffix}'},'packedPolicySize':0}),
        'GetCallerIdentity': ('sts.amazonaws.com', {}, {'userId':f'AROASYNTH:{suffix}','account':account,'arn':f'arn:aws:sts::{account}:assumed-role/AsteronSyntheticRole/asteron-session-{suffix}'}),
        'DescribeInstances': ('ec2.amazonaws.com', {'filters':[{'name':'instance-state-name','values':['running']}]}, {'reservationSet':{'items':[]}}),
        'DescribeSecurityGroups': ('ec2.amazonaws.com', {'groupIds':[f'sg-0{suffix}a51e0']}, {'securityGroupInfo':{'items':[]}}),
        'DescribeSubnets': ('ec2.amazonaws.com', {'subnetIds':[f'subnet-0{suffix}aa01']}, {'subnetSet':{'items':[]}}),
        'DescribeVpcs': ('ec2.amazonaws.com', {'vpcIds':[f'vpc-0{suffix}e0a1']}, {'vpcSet':{'items':[]}}),
        'ListBuckets': ('s3.amazonaws.com', {}, {'owner':{'displayName':'asteron','id':'synthetic-owner'},'buckets':[{'name':'asteron-engineering-prod','creationDate':'2025-11-14T12:00:00Z'}]}),
        'GetObject': ('s3.amazonaws.com', {'bucketName':'asteron-engineering-prod','key':f'exports/engineering-{suffix}.json'}, None),
        'ListObjectsV2': ('s3.amazonaws.com', {'bucketName':'asteron-engineering-prod','prefix':'exports/','maxKeys':1000}, None),
        'DescribeLogGroups': ('logs.amazonaws.com', {'logGroupNamePrefix':'/asteron/','limit':50}, {'logGroups':[]}),
        'GetSecretValue': ('secretsmanager.amazonaws.com', {'secretId':'asteron/web/prod/database','versionStage':'AWSCURRENT'}, None),
        'ListSecrets': ('secretsmanager.amazonaws.com', {'maxResults':100}, {'secretList':[]}),
        'GetParameter': ('ssm.amazonaws.com', {'name':'/asteron/web/prod/api-endpoint','withDecryption':False}, {'parameter':{'name':'/asteron/web/prod/api-endpoint','type':'String','version':17,'value':'https://api.asteron.example'}}),
        'DescribeDBInstances': ('rds.amazonaws.com', {'dBInstanceIdentifier':'asteron-prod-db'}, {'dBInstances':[]}),
        'DescribeLoadBalancers': ('elasticloadbalancing.amazonaws.com', {'loadBalancerArns':[f'arn:aws:elasticloadbalancing:{region}:{account}:loadbalancer/app/asteron-web/{suffix}']}, {'loadBalancers':[]}),
        'DescribeRepositories': ('ecr.amazonaws.com', {'repositoryNames':['asteron-web']}, {'repositories':[]}),
        'ListFunctions': ('lambda.amazonaws.com', {'maxItems':50}, {'functions':[]}),
        'ListDistributions': ('cloudfront.amazonaws.com', {}, {'distributionList':{'marker':'','maxItems':100,'isTruncated':False,'quantity':0,'items':[]}}),
        'GetAccountAuthorizationDetails': ('iam.amazonaws.com', {'filter':['User','Role','Group','LocalManagedPolicy']}, {'userDetailList':[],'groupDetailList':[],'roleDetailList':[],'policies':[],'isTruncated':False}),
        'ListRoles': ('iam.amazonaws.com', {'maxItems':1000}, {'roles':[],'isTruncated':False}),
        'ListUsers': ('iam.amazonaws.com', {'maxItems':1000}, {'users':[],'isTruncated':False}),
    }
    return table.get(event_name, ('ec2.amazonaws.com', {}, None))


def cloudtrail(event_time,event_name,source_ip,user_arn,account='111122223333',region='us-east-1',source=None,params=None,response=None,user_agent='aws-cli/2.15.0'):
    # If the caller supplies an AWS ARN, keep account identity internally consistent.
    arn_parts=user_arn.split(':')
    if len(arn_parts) > 4 and arn_parts[4].isdigit():
        account=arn_parts[4]
    ordinal=hashlib.sha256(f'{event_time}|{event_name}|{source_ip}|{user_arn}'.encode()).hexdigest()[:6]
    correct_source, default_params, default_response = _event_defaults(event_name, region, account, int(ordinal,16)%1000)
    source=correct_source
    final_params=dict(default_params)
    if isinstance(params,dict):
        # Ignore placeholder fields from older synthetic builds while allowing
        # event-specific details to enrich the TA-compatible defaults.
        final_params.update({k:v for k,v in params.items() if k not in {'resource','syntheticContext'}})
    final_response=default_response if response is None else response
    read_only=event_name.startswith(('Get','List','Describe'))
    data_event=event_name in {'GetObject'}

    role_name=user_arn.rsplit('/',1)[-1]
    assumed_arn=f'arn:aws:sts::{account}:assumed-role/{role_name}/asteron-session-{ordinal[:6]}'
    issuer_arn=f'arn:aws:iam::{account}:role/{role_name}'
    return json.dumps({
        'eventVersion':'1.10',
        'userIdentity':{
            'type':'AssumedRole','principalId':f'AROASYNTH:{role_name}',
            'arn':assumed_arn,'accountId':account,'accessKeyId':'ASIASYNTHETIC01',
            'sessionContext':{
                'sessionIssuer':{'type':'Role','principalId':'AROASYNTH','arn':issuer_arn,'accountId':account,'userName':role_name},
                'attributes':{'creationDate':event_time,'mfaAuthenticated':'false'}
            }
        },
        'eventTime':event_time,'eventSource':source,'eventName':event_name,'awsRegion':region,
        'sourceIPAddress':source_ip,'userAgent':user_agent,'requestParameters':final_params,
        'responseElements':final_response,'requestID':f'7d2c6f52-{ordinal}-synthetic',
        'eventID':f'11111111-2222-3333-4444-{ordinal.zfill(12)}','readOnly':read_only,
        'eventType':'AwsApiCall','managementEvent':not data_event,'recipientAccountId':account,
        'eventCategory':'Data' if data_event else 'Management'
    },separators=(',',':'))


def aws_vpc_flow(version,account_id,interface_id,src,dst,sport,dport,protocol,packets,bytes_count,start,end,action='ACCEPT',status='OK',vpc='vpc-0a57e0a1',subnet='subnet-0310aa01',instance='i-0a51a100',region='us-east-1',az='use1-az2',flow_direction='ingress',traffic_path=1):
    return f'{version} {account_id} {interface_id} {src} {dst} {sport} {dport} {protocol} {packets} {bytes_count} {start} {end} {action} {status} {vpc} {subnet} {instance} tcp 0 0 0 {region} {az} - - - - - {flow_direction} {traffic_path}'


def gitlab_audit(ts,author,ip,entity,event_type,target,details=None):
    return json.dumps({'created_at':ts,'author_name':author,'author_id':4102,'ip_address':ip,'entity_type':entity,'entity_path':'asteron/web-platform','target_type':event_type,'target_details':target,'event_type':event_type,'details':details or {}},separators=(',',':'))


def waf(ts,client_ip,host,uri,status,action,rule='Default',request_id='req-synthetic'):
    return json.dumps({'timestamp':ts,'webaclId':'asteron-public-web','terminatingRuleId':rule,'action':action,'httpSourceName':'ALB','httpRequest':{'clientIp':client_ip,'country':'US','headers':[{'name':'host','value':host},{'name':'user-agent','value':'Mozilla/5.0'}],'uri':uri,'httpMethod':'POST' if action!='ALLOW' else 'GET','requestId':request_id},'responseCodeSent':status},separators=(',',':'))


def dlp(ts,user,host,file_name,bytes_sent,destination,policy,severity='high',action='alert'):
    return json.dumps({'timestamp':ts,'user':user,'host':host,'file':file_name,'bytes':bytes_sent,'destination':destination,'policy':policy,'severity':severity,'action':action},separators=(',',':'))


def badge(ts,badge_id,employee_id,site,reader,result='GRANTED'):
    return json.dumps({'timestamp':ts,'badge_id':badge_id,'employee_id':employee_id,'site':site,'reader':reader,'result':result,'event_type':'badge_access'},separators=(',',':'))


def servicenow_audit(ts,user,action,table,record,source_ip,detail=''):
    return json.dumps({'sys_created_on':ts,'user_name':user,'action':action,'table_name':table,'documentkey':record,'source_ip':source_ip,'details':detail},separators=(',',':'))


def tenable_vuln(ts,scanner_ip,target_ip,target_host,plugin_id,plugin_name,severity,port,protocol='tcp',state='open',cve=None,cvss3=None,synopsis=None):
    sevmap={'info':0,'low':1,'medium':2,'high':3,'critical':4}
    fqdn=target_host.lower()+'.us.asteron.local' if '.' not in target_host else target_host.lower()
    cve=cve or ([] if severity in {'info','low'} else [f'CVE-2025-{int(plugin_id)%9000+1000:04d}'])
    cvss3=float(cvss3 if cvss3 is not None else {'info':0.0,'low':3.1,'medium':6.5,'high':8.2,'critical':9.8}.get(severity,5.0))
    synopsis=synopsis or f'{plugin_name} was identified on the target service.'
    return json.dumps({
        'timestamp':ts,'scanner_ip':scanner_ip,
        'ipv4':target_ip,'ip':target_ip,'asset_fqdn':fqdn,'asset_hostname':target_host,
        'asset':{'uuid':hashlib.md5(target_host.encode()).hexdigest(),'ipv4':target_ip,'hostname':target_host,'fqdn':fqdn},
        'plugin':{
            'id':int(plugin_id),'name':plugin_name,'family':'General','synopsis':synopsis,
            'description':f'Synthetic Tenable-compatible result for {plugin_name}.',
            'cve':cve,'cvss3_base_score':cvss3,'cvss_base_score':max(0.0,cvss3-0.4),
            'risk_factor':severity.capitalize()
        },
        'severity':severity,'severity_id':sevmap.get(severity,2),
        'port':{'port':int(port),'protocol':protocol},'state':state
    },separators=(',',':'))


def sccm_event(ts,site_code,device,user,operation,status,package_id='AUG00042'):
    return json.dumps({'timestamp':ts,'site_code':site_code,'device':device,'user':user,'operation':operation,'status':status,'package_id':package_id,'component':'ConfigMgrClient'},separators=(',',':'))


def wsus_event(ts,device,update_id,title,status,server='USHQ-WSUS-01'):
    return json.dumps({'timestamp':ts,'device':device,'update_id':update_id,'title':title,'status':status,'server':server},separators=(',',':'))


def ivanti_event(ts,device,user,action,result,job='Inventory Scan',update_id=None,package_name=None,version=None,file_name=None):
    update_id=update_id or f'IVANTI-{hashlib.md5((device+ts).encode()).hexdigest()[:8].upper()}'
    package_name=package_name or 'Asteron Security Update'
    version=version or '2026.04.1'
    file_name=file_name or f'{package_name.lower().replace(" ","-")}-{version}.msi'
    return json.dumps({
        'timestamp':ts,'device':device,'target_device':device,'user':user,'action':action,'result':result,
        'job':job,'product':'Ivanti Endpoint Manager','update_id':update_id,'package_id':update_id,
        'package_name':package_name,'package_version':version,'file_name':file_name,
        'status':'success' if str(result).lower() in {'success','installed','completed'} else str(result).lower()
    },separators=(',',':'))


def vdi_session(ts,user,client,desktop,action,broker='USHQ-VDI-01',protocol='HDX'):
    return json.dumps({'timestamp':ts,'user':user,'client_name':client,'desktop':desktop,'action':action,'broker':broker,'protocol':protocol},separators=(',',':'))


def mft_transfer(ts,user,src_host,file_name,bytes_count,destination,direction='upload',status='success',transfer_id='tx-synthetic'):
    return json.dumps({'timestamp':ts,'user':user,'source_host':src_host,'file_name':file_name,'bytes':bytes_count,'destination':destination,'direction':direction,'status':status,'transfer_id':transfer_id},separators=(',',':'))


def defender_event(ts,device,title,severity,account,initiating_process,file_name,action='BehaviorObserved',category='AdvancedHunting-DeviceEvents'):
    props={
        'Timestamp':ts,'DeviceId':hashlib.sha256(device.encode()).hexdigest()[:40],
        'DeviceName':device,'ActionType':action,'FileName':file_name,
        'FolderPath':r'C:\Windows\System32' if device.upper().startswith('US') else '/usr/bin',
        'AccountDomain':'US','AccountName':account.split('\\')[-1],
        'InitiatingProcessFileName':initiating_process,
        'InitiatingProcessCommandLine':initiating_process,
        'InitiatingProcessAccountDomain':'US',
        'InitiatingProcessAccountName':account.split('\\')[-1],
        'ReportId':int(hashlib.md5((device+ts+title).encode()).hexdigest()[:8],16),
        'AdditionalFields':json.dumps({'AlertTitle':title,'Severity':severity},separators=(',',':'))
    }
    return json.dumps({'time':ts,'tenantId':'11111111-2222-3333-4444-555555555555','category':category,'properties':props},separators=(',',':'))


def trellix_event(ts,host,threat,severity,process,child='',action='Blocked',user='SYSTEM'):
    return json.dumps({'eventTime':ts,'hostname':host,'product':'Trellix Endpoint Security','threatName':threat,'severity':severity,'process':process,'child_process':child,'action':action,'user':user},separators=(',',':'))


def radius_auth(ts,server,user,nas,src_ip,result='Access-Accept',method='EAP-TLS'):
    return f'{ts} server={server} user="{user}" nas="{nas}" calling_station={src_ip} auth_method={method} result={result}'


def tacacs_auth(ts,server,user,device,src_ip,service='shell',result='PASS',reason=''):
    base=f'{ts} server={server} user={user} device={device} src={src_ip} service={service} result={result}'
    return base + (f' reason="{reason}"' if reason else '')


def defender_alert_info(ts,alert_id,title,severity,detection_category,attack_techniques='',
                        service_source='Microsoft Defender for Endpoint',
                        detection_source='Microsoft Defender for Endpoint',
                        machine_group='Asteron-Enterprise'):
    props={
        'Timestamp':ts,'AlertId':alert_id,'Title':title,'Category':detection_category,
        'Severity':severity,'ServiceSource':service_source,'DetectionSource':detection_source,
        'AttackTechniques':attack_techniques,'MachineGroup':machine_group
    }
    return json.dumps({'time':ts,'tenantId':'11111111-2222-3333-4444-555555555555',
                       'category':'AdvancedHunting-AlertInfo','properties':props},separators=(',',':'))


def defender_alert_evidence(ts,alert_id,title,severity,device,account,file_name,folder_path,
                            process_command_line='',threat_family='',sha1='',sha256='',
                            detection_category='Malware',remediation_status='Remediated',
                            remediation_action='Quarantine',remote_ip='',remote_url=''):
    device_id=hashlib.sha256(device.encode()).hexdigest()[:40]
    if not sha1 and file_name:
        sha1=hashlib.sha1((device+'|'+file_name+'|'+alert_id).encode()).hexdigest().upper()
    if not sha256 and file_name:
        sha256=hashlib.sha256((device+'|'+file_name+'|'+alert_id).encode()).hexdigest().upper()
    user=account.split('\\')[-1]
    domain=account.split('\\')[0] if '\\' in account else 'US'
    additional=json.dumps({'ThreatName':title,'RemediationStatus':remediation_status,
                           'RemediationAction':remediation_action},separators=(',',':'))
    props={
        'Timestamp':ts,'AlertId':alert_id,'Title':title,
        'Categories':json.dumps([detection_category],separators=(',',':')),'AttackTechniques':'',
        'ServiceSource':'Microsoft Defender for Endpoint','DetectionSource':'Microsoft Defender for Endpoint',
        'EntityType':'File' if file_name else 'Process','EvidenceRole':'Impacted','EvidenceDirection':'',
        'FileName':file_name,'FolderPath':folder_path,'SHA1':sha1,'SHA256':sha256,'FileSize':0,
        'ThreatFamily':threat_family,'RemoteIP':remote_ip,'RemoteUrl':remote_url,
        'AccountName':user,'AccountDomain':domain,'AccountSid':'','AccountObjectId':'','AccountUpn':'',
        'DeviceId':device_id,'DeviceName':device,'LocalIP':'','ProcessCommandLine':process_command_line,
        'AdditionalFields':additional,'Severity':severity,'MachineGroup':'Asteron-Enterprise'
    }
    return json.dumps({'time':ts,'tenantId':'11111111-2222-3333-4444-555555555555',
                       'category':'AdvancedHunting-AlertEvidence','properties':props},separators=(',',':'))


def print_event(ts,user,client,printer,document,pages,status='printed'):
    return json.dumps({'timestamp':ts,'user':user,'client':client,'printer':printer,'document':document,'pages':pages,'status':status},separators=(',',':'))
