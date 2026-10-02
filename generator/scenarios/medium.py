"""Load the canonical static SILK SPECTER Medium campaign evidence.

Medium answer-bearing events are committed under scenario_data/medium and must not
be synthesized at generation time. The generator may add background/noise around
these records, but question answers remain tied to these immutable events.
"""
from __future__ import annotations
from pathlib import Path
import json

from core.state import Event
from core.scenario import parse_utc


def build_campaign(store, ctx, environment):
    path = Path(__file__).resolve().parents[2] / "scenario_data" / "medium" / "attack_events.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"Missing static Medium campaign: {path}")

    loaded = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("scenario") != "medium":
            raise ValueError(f"Static Medium event line {line_number} has scenario={row.get('scenario')!r}")
        ctx.require_in_window(parse_utc(row["time"]))
        store.events.append(Event(**row))
        loaded += 1

    return {
        "campaign": "medium",
        "static_events": loaded,
        "source": str(path),
    }
