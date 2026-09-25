from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address


@dataclass(frozen=True)
class NetworkFlow:
    """Semantic network flow used to keep multi-source telemetry coherent.

    Scenario authors should create one flow object for a semantic connection and
    render firewall/Zeek/endpoint/cloud observations from that same object rather
    than independently randomizing tuples in each source.
    """
    flow_id: str
    start: datetime
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    transport: str = 'tcp'
    bytes_out: int = 0
    bytes_in: int = 0
    duration: float = 0.0
    src_host: str | None = None
    dest_host: str | None = None
    service: str | None = None
    nat_src_ip: str | None = None
    nat_src_port: int | None = None
    nat_dest_ip: str | None = None
    nat_dest_port: int | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        ip_address(self.src_ip)
        ip_address(self.dest_ip)
        if self.nat_src_ip:
            ip_address(self.nat_src_ip)
        if self.nat_dest_ip:
            ip_address(self.nat_dest_ip)
        for p in [self.src_port, self.dest_port, self.nat_src_port, self.nat_dest_port]:
            if p is not None and not 0 <= int(p) <= 65535:
                raise ValueError(f'invalid port {p} in {self.flow_id}')
        if self.transport.lower() not in {'tcp','udp','icmp','icmp6'}:
            raise ValueError(f'unsupported transport {self.transport} in {self.flow_id}')
        if self.bytes_out < 0 or self.bytes_in < 0 or self.duration < 0:
            raise ValueError(f'negative flow metric in {self.flow_id}')

    @property
    def tuple5(self) -> tuple[str,int,str,int,str]:
        return (self.src_ip, self.src_port, self.dest_ip, self.dest_port, self.transport.lower())


class NetworkLedger:
    """Instructor-side correlation ledger for semantic network actions."""
    def __init__(self) -> None:
        self._flows: dict[str, NetworkFlow] = {}
        self._observations: dict[str, set[str]] = {}

    def add_flow(self, flow: NetworkFlow) -> NetworkFlow:
        flow.validate()
        if flow.flow_id in self._flows and self._flows[flow.flow_id] != flow:
            raise ValueError(f'flow_id reused with different tuple: {flow.flow_id}')
        self._flows[flow.flow_id] = flow
        self._observations.setdefault(flow.flow_id, set())
        return flow

    def observe(self, flow_id: str, source_family: str) -> None:
        if flow_id not in self._flows:
            raise KeyError(f'unknown flow {flow_id}')
        self._observations[flow_id].add(source_family)

    def require_observations(self, flow_id: str, required: set[str]) -> None:
        missing = required - self._observations.get(flow_id, set())
        if missing:
            raise ValueError(f'{flow_id} missing network observations: {sorted(missing)}')
