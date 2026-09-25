from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict
import csv, hashlib, json, re, uuid
from datetime import datetime, timezone


SOURCETYPE_ALIASES = {
    'zeek:conn': 'bro:conn:json',
    'zeek:dns': 'bro:dns:json',
    'zeek:http': 'bro:http:json',
    'zeek:tls': 'bro:ssl:json',
    'zeek:ssl': 'bro:ssl:json',
    'zeek:smb_files': 'bro:smb_files:json',
    'zeek:dce_rpc': 'bro:dce_rpc:json',
    'zeek:files': 'bro:files:json',
    'zeek:x509': 'bro:x509:json',
    'fortigate:traffic': 'fortigate_traffic',
    'junos:syslog': 'juniper',
    'ms:defender:endpoint': 'ms:defender:eventhub',
}


@dataclass
class Event:
    event_id: str
    activity_id: str
    scenario: str
    time: str
    host: str
    source: str
    sourcetype: str
    raw: str
    truth_label: str = 'background'
    technique: str = ''
    question_tags: str = ''

class EventStore:
    def __init__(self, scenario='easy'):
        self.scenario = scenario
        self.events=[]
        self._records=defaultdict(int)

    def opaque_id(self, key: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, 'asteron-v3:' + key))

    def record_id(self, host: str, channel: str) -> int:
        # Retained for compatibility; source-native Windows/Sysmon builders should
        # prefer record_id_at() so IDs remain monotonic by event time.
        k=(host,channel)
        self._records[k]+=1
        return 100000 + self._records[k]

    def record_id_at(self, host: str, channel: str, when) -> int:
        if isinstance(when, str):
            from datetime import datetime
            when=datetime.fromisoformat(when.replace('Z','+00:00'))
        base=int(when.timestamp()*1_000_000)*1000
        k=(host,channel,base)
        self._records[k]+=1
        return base + self._records[k]

    def add(self, *, key, activity_id, time, host, source, sourcetype, raw,
            truth_label='background', technique='', question_tags=''):
        # Splunk_TA_windows in the target lab expects generic XmlWinEventLog
        # with the channel represented by source (for example
        # XmlWinEventLog:Security or XmlWinEventLog:Microsoft-Windows-Sysmon/Operational).
        # Normalize any legacy channel-specific generator metadata back to the
        # generic TA-compatible sourcetype.
        if sourcetype.startswith('XmlWinEventLog'):
            sourcetype = 'XmlWinEventLog'
        sourcetype = SOURCETYPE_ALIASES.get(sourcetype, sourcetype)
        self.events.append(Event(
            event_id=self.opaque_id(key), activity_id=activity_id, scenario=self.scenario,
            time=time, host=host, source=source, sourcetype=sourcetype, raw=raw,
            truth_label=truth_label, technique=technique, question_tags=question_tags))

    @staticmethod
    def safe_name(s):
        return re.sub(r'[^A-Za-z0-9_.-]+','_',s).strip('_')

    def write(self, outdir: Path):
        outdir.mkdir(parents=True,exist_ok=True)
        groups=defaultdict(list)
        for e in sorted(self.events,key=lambda x:(x.time,x.event_id)):
            groups[(e.host,e.source,e.sourcetype)].append(e)
        manifest=[]
        rawdir=outdir/'raw'; rawdir.mkdir(exist_ok=True)
        # Regeneration must not leave stale shards from a previous build.
        for stale in rawdir.glob('*.log'):
            stale.unlink()
        for i,((host,source,st),events) in enumerate(sorted(groups.items()),1):
            fn=f'{i:04d}__{self.safe_name(host)}__{self.safe_name(st)}.log'
            p=rawdir/fn
            with p.open('w',encoding='utf-8',newline='\n') as f:
                for e in events:
                    f.write(e.raw.rstrip('\n')+'\n')
            manifest.append({'file':f'raw/{fn}','host':host,'source':source,'sourcetype':st,'event_count':len(events)})
        with (outdir/'ingest_manifest.csv').open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=['file','host','source','sourcetype','event_count']); w.writeheader(); w.writerows(manifest)

        # Canonical Splunk ingest stream. Each line uses Splunk's HEC event
        # envelope so _time and metadata are explicit while the indexed _raw
        # remains the source-native event string. This avoids relying on
        # heuristic timestamp recognition across dozens of vendor formats.
        hecdir=outdir/'hec'; hecdir.mkdir(exist_ok=True)
        hecfile=hecdir/'events.jsonl'
        with hecfile.open('w',encoding='utf-8',newline='\n') as f:
            for e in sorted(self.events,key=lambda x:(x.time,x.event_id)):
                dt=datetime.fromisoformat(e.time.replace('Z','+00:00'))
                envelope={
                    'time':dt.timestamp(),
                    'host':e.host,
                    'source':e.source,
                    'sourcetype':e.sourcetype,
                    'event':e.raw.rstrip('\n'),
                }
                f.write(json.dumps(envelope,separators=(',',':'))+'\n')
        # Ground truth is intentionally separate from participant raw. Keep it
        # scenario-scoped so future Medium/Hard or other APT builds cannot
        # overwrite one another. The legacy Easy path is retained for v0.2.x
        # compatibility with the validated test suite and instructor tooling.
        fields=['event_id','activity_id','scenario','time','host','source','sourcetype','truth_label','technique','question_tags']
        gt_dir=outdir.parent/'ground_truth'; gt_dir.mkdir(exist_ok=True)
        targets=[gt_dir/f'{self.scenario}_events.csv']
        if self.scenario == 'easy':
            targets.append(outdir.parent/'ground_truth_events.csv')
        for target in targets:
            with target.open('w',newline='',encoding='utf-8') as f:
                w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
                for e in sorted(self.events,key=lambda x:x.time):
                    d=asdict(e); d.pop('raw'); w.writerow({k:d[k] for k in fields})
        summary={
            'scenario':self.scenario,'events':len(self.events),'files':len(manifest),
            'sourcetypes':sorted({e.sourcetype for e in self.events}),
            'hosts':len({e.host for e in self.events}),
            'first_time':min(e.time for e in self.events) if self.events else None,
            'last_time':max(e.time for e in self.events) if self.events else None,
            'canonical_ingest_file':'hec/events.jsonl',
        }
        (outdir/'manifest.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
        return summary
