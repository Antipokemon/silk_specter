"""Load the canonical static SILK SPECTER Easy campaign evidence.

Easy originally authored the campaign directly inside ``generator/generate.py``.
The validated answer-bearing records are now committed under
``scenario_data/easy/attack_events.jsonl`` so all three tracks use the same
contract: static campaign evidence plus regenerable background/noise.
"""
from __future__ import annotations
from pathlib import Path
import json

from core.state import Event
from core.scenario import parse_utc


def build_campaign(store, ctx, environment):
    path = Path(__file__).resolve().parents[2] / "scenario_data" / "easy" / "attack_events.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"Missing static Easy campaign: {path}")

    loaded = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("scenario") != "easy":
            raise ValueError(f"Static Easy event line {line_number} has scenario={row.get('scenario')!r}")
        ctx.require_in_window(parse_utc(row["time"]))
        store.events.append(Event(**row))
        loaded += 1

    return {"campaign": "easy", "static_events": loaded, "source": str(path)}
