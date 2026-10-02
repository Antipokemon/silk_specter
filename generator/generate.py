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
from renderers import windows, zeek, network_devices, apps
from background import add_enterprise_background, add_defender_detection_background
from scenarios.easy import build_campaign as build_easy_campaign
from scenarios.medium import build_campaign as build_medium_campaign
from scenarios.hard import build_campaign as build_hard_campaign
from notables import build_notables

DEFAULT_BACKGROUND_EVENTS = 5000
DEFAULT_ENTERPRISE_BACKGROUND_EVENTS = 45000

CFG=json.loads((ROOT/'config/scenarios/easy.json').read_text())
CTX=ScenarioContext.from_dict('easy', CFG)
SITES=json.loads((ROOT/'config/sites.json').read_text())['sites']
SITE_BY_CODE={s['code']:s for s in SITES}

def iso(dt): return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
def zts(dt): return dt.timestamp()
def uuidg(name): return '{'+str(uuid.uuid5(uuid.NAMESPACE_DNS,'asteron:'+name))+'}'
def zuid(name): return 'C'+uuid.uuid5(uuid.NAMESPACE_DNS,'zeek:'+name).hex[:17]

def resolve_generation_counts(cfg, background_override=None, enterprise_background_override=None):
    generation = cfg.get('generation', {})
    background = generation.get('background_events', DEFAULT_BACKGROUND_EVENTS) if background_override is None else background_override
    enterprise = generation.get('enterprise_background_events', DEFAULT_ENTERPRISE_BACKGROUND_EVENTS) if enterprise_background_override is None else enterprise_background_override
    background = int(background)
    enterprise = int(enterprise)
    if background < 0 or enterprise < 0:
        raise ValueError('Generation event counts must be non-negative integers')
    return background, enterprise

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

    base_cfg=json.loads((ROOT/'config/scenarios'/f'{args.scenario}.json').read_text(encoding='utf-8'))
    if base_cfg.get('static_campaign'):
        if args.start and args.start != base_cfg['start']:
            raise SystemExit('Static CTF campaign evidence uses a fixed authored window; changing --start would invalidate question/reference times.')
        if args.end and args.end != base_cfg['end']:
            raise SystemExit('Static CTF campaign evidence uses a fixed authored window; changing --end would invalidate question/reference times.')
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
        build_easy_campaign(store, CTX, {'config': CFG, 'sites': scoped_sites})
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
    notable_summary=build_notables(ROOT,args.scenario,out,CFG)
    summary['notables']=notable_summary
    (out/'manifest.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))

if __name__=='__main__': main()
