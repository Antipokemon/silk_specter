#!/usr/bin/env python3
"""Build deterministic synthetic ES-style notable events for a SILK SPECTER track.

The main dataset contains source telemetry.  This module creates a separate
notable feed containing the authored campaign findings plus benign/questionable
alert noise.  The participant feed never includes the instructor disposition.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
import argparse
import csv
import json
import random
import uuid

ROOT = Path(__file__).resolve().parents[1]

NOISE_CATALOG = [
    ("Multiple Failed Logons From Workstation", "medium", "access"),
    ("Administrative PowerShell On Server", "low", "endpoint"),
    ("New Service Installation", "medium", "endpoint"),
    ("Rare DNS Query From User Segment", "low", "network"),
    ("Large File Transfer To Approved Partner", "medium", "network"),
    ("Unsigned Process From User Profile", "medium", "endpoint"),
    ("Remote Administration Tool Usage", "medium", "endpoint"),
    ("Cloud Console Login From New ASN", "medium", "access"),
    ("Service Account Interactive Logon", "high", "access"),
    ("Endpoint Malware Heuristic", "high", "endpoint"),
    ("Firewall Deny Burst", "low", "network"),
    ("Privileged Group Membership Change", "high", "access"),
    ("Vulnerability Scanner Fan-Out", "informational", "network"),
    ("MFA Retry Pattern", "low", "access"),
    ("High Volume SMB Read", "medium", "network"),
    ("Unusual Scheduled Task", "medium", "endpoint"),
    ("DLP Policy Match With User Justification", "medium", "threat"),
    ("SSH Login From Management Segment", "low", "access"),
    ("New OAuth Application Consent", "medium", "access"),
    ("Rare User Agent To SaaS Service", "low", "network"),
]

SEVERITY_WORDS = {
    "critical": "critical",
    "exfil": "critical",
    "lsass": "high",
    "credential": "high",
    "lateral": "high",
    "pivot": "high",
    "exploit": "high",
    "shell": "high",
    "archive": "medium",
    "vpn": "medium",
    "cloud": "medium",
    "scanner": "informational",
    "recon": "medium",
}


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def q(value: object) -> str:
    text = str(value if value is not None else "")
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def infer_urgency(title: str) -> str:
    low = title.lower()
    for token, urgency in SEVERITY_WORDS.items():
        if token in low:
            return urgency
    return "medium"


def infer_domain(title: str) -> str:
    low = title.lower()
    if any(x in low for x in ("vpn", "logon", "account", "credential", "mfa")):
        return "access"
    if any(x in low for x in ("cloud", "gitlab", "oauth", "saas")):
        return "threat"
    if any(x in low for x in ("shell", "process", "lsass", "archive", "service", "scheduled")):
        return "endpoint"
    return "network"


def event_time_for_activity(activity_rows, activity_id: str, offset: int) -> datetime:
    rows = activity_rows.get(activity_id, [])
    if not rows:
        raise ValueError(f"No ground-truth events found for activity {activity_id}")
    return min(parse_iso(r["time"]) for r in rows) + timedelta(seconds=60 + offset)


def notable_raw(*, event_id: str, rule_name: str, urgency: str, domain: str,
                scenario: str, source_index: str, src: str, dest: str, user: str,
                drilldown_search: str, event_time: float) -> str:
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:rule:{scenario}:{rule_name}"))
    fields = [
        ("event_id", event_id),
        ("orig_sid", event_id),
        ("rule_id", rule_id),
        ("rule_name", rule_name),
        ("rule_title", rule_name),
        ("search_name", rule_name),
        ("urgency", urgency),
        ("severity", urgency),
        ("status", "1"),
        ("status_label", "New"),
        ("owner", "unassigned"),
        ("security_domain", domain),
        ("app", "SA-SilkSpecter"),
        ("notable_type", "notable"),
        ("info_min_time", int(event_time) - 300),
        ("info_max_time", int(event_time) + 300),
        ("scenario", scenario),
        ("ctf_track", scenario),
        ("source_index", source_index),
        ("src", src),
        ("dest", dest),
        ("user", user),
        ("drilldown_search", drilldown_search),
    ]
    return " ".join(f"{key}={q(value)}" for key, value in fields)


def build_notables(root: Path, scenario: str, dataset_dir: Path, cfg: dict) -> dict:
    static_rel = cfg.get("static_campaign")
    if not static_rel:
        raise ValueError(f"Scenario {scenario!r} has no static_campaign configured")
    truth_path = root / static_rel
    findings_path = root / "instructor" / "findings" / f"{scenario}_expected_findings.csv"
    if not truth_path.is_file():
        raise FileNotFoundError(f"Missing static campaign ground truth: {truth_path}")
    if not findings_path.is_file():
        raise FileNotFoundError(f"Missing expected findings: {findings_path}")

    truth = [json.loads(line) for line in truth_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    with findings_path.open(newline="", encoding="utf-8") as f:
        findings = list(csv.DictReader(f))

    activity_rows = defaultdict(list)
    for row in truth:
        activity_rows[row["activity_id"]].append(row)

    start = parse_iso(cfg["start"])
    end = parse_iso(cfg["end"])
    seed = int(cfg.get("seed", 0)) + 47001
    rng = random.Random(seed)
    noise_count = int(cfg.get("notables", {}).get("noise_events", 0))
    source_index = "<index>"

    records = []
    instructor_rows = []

    # Campaign/expected findings. Multiple findings may map to the same activity;
    # give each a stable offset so their event times remain deterministic.
    per_activity = defaultdict(int)
    for finding in findings:
        activity = finding["activity_id"]
        offset = per_activity[activity]
        per_activity[activity] += 1
        dt = event_time_for_activity(activity_rows, activity, offset)
        rule = finding["detection_name"]
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:notable:{scenario}:{finding['finding_id']}"))
        evidence = activity_rows[activity][0]
        dest = evidence.get("host", "-") or "-"
        src = "-"
        user = "-"
        drill = f"index={source_index} earliest={int(dt.timestamp())-300} latest={int(dt.timestamp())+300}"
        records.append({
            "time": dt.timestamp(),
            "host": "SILK-SPECTER-ES",
            "source": "notable",
            "sourcetype": "stash",
            "event": notable_raw(
                event_id=event_id,
                rule_name=rule,
                urgency=infer_urgency(rule),
                domain=infer_domain(rule),
                scenario=scenario,
                source_index=source_index,
                src=src,
                dest=dest,
                user=user,
                drilldown_search=drill,
                event_time=dt.timestamp(),
            ),
        })
        instructor_rows.append({
            "event_id": event_id,
            "scenario": scenario,
            "time": dt.isoformat().replace("+00:00", "Z"),
            "rule_name": rule,
            "expected_disposition": finding["expected_disposition"],
            "activity_id": activity,
            "kind": "campaign",
            "notes": finding.get("notes", ""),
        })

    # Benign/questionable alert noise. It is intentionally more numerous as
    # difficulty increases, but remains deterministic for stable CTF triage.
    sites = list(cfg.get("scope_sites", [])) or ["USHQ"]
    window_seconds = max(1, int((end - start).total_seconds()))
    for i in range(noise_count):
        title, urgency, domain = rng.choice(NOISE_CATALOG)
        dt = start + timedelta(seconds=rng.randint(900, max(901, window_seconds - 900)))
        site = rng.choice(sites)
        site_octet = 40 + (sum(ord(ch) for ch in site) % 20)
        src = f"10.{site_octet}.40.{rng.randint(20, 220)}"
        dest = f"{site}-SRV-{rng.randint(1, 24):02d}"
        user = f"user{rng.randint(100, 999)}"
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:notable-noise:{scenario}:{i}"))
        drill = f"index={source_index} earliest={int(dt.timestamp())-300} latest={int(dt.timestamp())+300}"
        records.append({
            "time": dt.timestamp(),
            "host": "SILK-SPECTER-ES",
            "source": "notable",
            "sourcetype": "stash",
            "event": notable_raw(
                event_id=event_id,
                rule_name=title,
                urgency=urgency,
                domain=domain,
                scenario=scenario,
                source_index=source_index,
                src=src,
                dest=dest,
                user=user,
                drilldown_search=drill,
                event_time=dt.timestamp(),
            ),
        })
        instructor_rows.append({
            "event_id": event_id,
            "scenario": scenario,
            "time": dt.isoformat().replace("+00:00", "Z"),
            "rule_name": title,
            "expected_disposition": "benign" if i % 4 else "questionable",
            "activity_id": "",
            "kind": "noise",
            "notes": "Synthetic alert noise; participant must triage against raw telemetry.",
        })

    records.sort(key=lambda r: (r["time"], r["event"]))
    instructor_rows.sort(key=lambda r: (r["time"], r["event_id"]))

    out = dataset_dir / "notables"
    raw_dir = out / "raw"
    hec_dir = out / "hec"
    raw_dir.mkdir(parents=True, exist_ok=True)
    hec_dir.mkdir(parents=True, exist_ok=True)

    (raw_dir / "notables.log").write_text(
        "\n".join(r["event"] for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    with (hec_dir / "events.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for row in records:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

    manifest = {
        "scenario": scenario,
        "events": len(records),
        "campaign_notables": len(findings),
        "noise_notables": noise_count,
        "sourcetype": "stash",
        "source": "notable",
        "canonical_ingest_file": "hec/events.jsonl",
        "participant_filter": f"index=notable source=notable sourcetype=stash scenario={scenario}",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    with (out / "expected_counts.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["sourcetype", "expected_count"])
        w.writeheader()
        w.writerow({"sourcetype": "stash", "expected_count": len(records)})
    with (out / "ingest_manifest.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file", "host", "source", "sourcetype", "event_count"])
        w.writeheader()
        w.writerow({"file": "raw/notables.log", "host": "SILK-SPECTER-ES", "source": "notable", "sourcetype": "stash", "event_count": len(records)})

    instructor_path = root / "instructor" / "findings" / f"{scenario}_notable_ground_truth.csv"
    with instructor_path.open("w", newline="", encoding="utf-8") as f:
        fields = ["event_id", "scenario", "time", "rule_name", "expected_disposition", "activity_id", "kind", "notes"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(instructor_rows)

    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Build deterministic SILK SPECTER notable feed")
    ap.add_argument("--scenario", choices=["easy", "medium", "hard"], required=True)
    ap.add_argument("--dataset", help="Dataset directory; default dataset/<scenario>")
    args = ap.parse_args()
    cfg = json.loads((ROOT / "config" / "scenarios" / f"{args.scenario}.json").read_text(encoding="utf-8"))
    dataset = Path(args.dataset) if args.dataset else ROOT / "dataset" / args.scenario
    print(json.dumps(build_notables(ROOT, args.scenario, dataset, cfg), indent=2))


if __name__ == "__main__":
    main()
