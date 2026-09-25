from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

UTC = timezone.utc


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


@dataclass(frozen=True)
class ScenarioContext:
    name: str
    slug: str
    status: str
    start: datetime
    end: datetime
    seed: int
    index: str
    config: dict

    @classmethod
    def from_dict(cls, slug: str, cfg: dict) -> 'ScenarioContext':
        return cls(
            name=cfg['name'], slug=slug, status=cfg.get('status', 'authoring'),
            start=parse_utc(cfg['start']), end=parse_utc(cfg['end']),
            seed=int(cfg['seed']), index=cfg['index'], config=cfg,
        )

    def at(self, day: int, hour: int = 0, minute: int = 0, second: int = 0, microsecond: int = 0) -> datetime:
        base = self.start.replace(hour=0, minute=0, second=0, microsecond=0)
        dt = base + timedelta(days=day, hours=hour, minutes=minute, seconds=second, microseconds=microsecond)
        self.require_in_window(dt)
        return dt

    def require_in_window(self, dt: datetime) -> None:
        dt = dt.astimezone(UTC)
        if not self.start <= dt <= self.end:
            raise ValueError(f'{dt.isoformat()} falls outside {self.slug} window {self.start.isoformat()}..{self.end.isoformat()}')

    @property
    def days(self) -> int:
        return (self.end.date() - self.start.date()).days + 1


def load_scenario(root: Path, slug: str, start_override: str | None = None, end_override: str | None = None) -> ScenarioContext:
    path = root / 'config' / 'scenarios' / f'{slug}.json'
    if not path.exists():
        raise SystemExit(f'Unknown scenario {slug!r}; expected {path}')
    cfg = json.loads(path.read_text(encoding='utf-8'))
    if start_override:
        cfg['start'] = start_override
    if end_override:
        cfg['end'] = end_override
    ctx = ScenarioContext.from_dict(slug, cfg)
    if ctx.end <= ctx.start:
        raise SystemExit('Scenario end must be after scenario start')
    return ctx
