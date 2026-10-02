"""Load the canonical static SILK SPECTER Hard campaign evidence.

Hard answer-bearing events are committed under scenario_data/hard. Generation may
add background/noise, but it must never synthesize or mutate challenge evidence.
"""
from __future__ import annotations
from pathlib import Path
import json

from core.state import Event
from core.scenario import parse_utc


def build_campaign(store, ctx, environment):
    path = Path(__file__).resolve().parents[2] / "scenario_data" / "hard" / "attack_events.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"Missing static Hard campaign: {path}")
    loaded = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("scenario") != "hard":
            raise ValueError(f"Static Hard event line {line_number} has scenario={row.get('scenario')!r}")
        ctx.require_in_window(parse_utc(row["time"]))
        store.events.append(Event(**row))
        loaded += 1
    return {"campaign":"hard","static_events":loaded,"source":str(path)}
