"""Read the live state of a wireguard interface.

Everything here is read-only and targets the network namespace of the wireguard
container, which the panel shares.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from ipaddress import ip_network

from .model import ABSENT, InterfaceConfig, address_cidr, normalize_cidr, to_int
from .runner import ExecResult, Runner

WG_LIST_TIMEOUT = 10.0


@dataclass
class PeerRuntime:
    public_key: str = ""
    preshared_key: str = ABSENT
    endpoint: str = ABSENT
    allowed_ips: list[str] = field(default_factory=list)
    latest_handshake: int = 0
    rx: int = 0
    tx: int = 0
    persistent_keepalive: int = 0

    @property
    def key_id(self) -> str:
        return self.public_key[:12] + "..." if len(self.public_key) > 15 else self.public_key

    def allowed_ip_set(self) -> frozenset[str]:
        return frozenset(
            cidr for cidr in (normalize_cidr(a) for a in self.allowed_ips) if cidr
        )

    def to_dict(self) -> dict:
        return {
            "public_key": self.public_key,
            "key_id": self.key_id,
            "endpoint": self.endpoint,
            "allowed_ips": list(self.allowed_ips),
            "latest_handshake": self.latest_handshake,
            "rx": self.rx,
            "tx": self.tx,
            "persistent_keepalive": self.persistent_keepalive,
            "has_preshared_key": self.preshared_key not in ("", ABSENT, "off"),
        }


@dataclass
class InterfaceRuntime:
    name: str = ""
    exists: bool = False
    private_key: str = ABSENT
    public_key: str = ABSENT
    listen_port: int = 0
    fwmark: str = "off"
    peers: list[PeerRuntime] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    mtu: int | None = None
    up: bool = False
    routes: list[str] = field(default_factory=list)

    def peer_by_key(self, public_key: str) -> PeerRuntime | None:
        for peer in self.peers:
            if peer.public_key == public_key:
                return peer
        return None

    @property
    def has_private_key(self) -> bool:
        return self.private_key not in ("", ABSENT)

    def to_dict(self, *, redact: bool = True) -> dict:
        return {
            "name": self.name,
            "exists": self.exists,
            "public_key": self.public_key,
            "has_private_key": self.has_private_key,
            "private_key": "(redacted)" if redact else self.private_key,
            "listen_port": self.listen_port,
            "fwmark": self.fwmark,
            "addresses": list(self.addresses),
            "mtu": self.mtu,
            "up": self.up,
            "routes": list(self.routes),
            "peers": [peer.to_dict() for peer in self.peers],
        }


def list_interfaces(runner: Runner) -> list[str]:
    result = runner.exec(["wg", "show", "interfaces"], timeout=WG_LIST_TIMEOUT)
    if not result.ok:
        return []
    return [name for name in result.stdout.split() if name]


def _ip_json(runner: Runner, argv: Sequence[str]) -> list[dict]:
    result: ExecResult = runner.exec(list(argv), timeout=WG_LIST_TIMEOUT)
    if not result.ok or not result.stdout.strip():
        return []
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return [item for item in data if isinstance(item, dict)]


def _parse_dump(text: str) -> InterfaceRuntime:
    runtime = InterfaceRuntime()
    device_seen = False
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 4 and not device_seen:
            runtime.private_key = parts[0] or ABSENT
            runtime.public_key = parts[1] or ABSENT
            runtime.listen_port = to_int(parts[2]) or 0
            runtime.fwmark = parts[3] or "off"
            device_seen = True
        elif len(parts) >= 8:
            runtime.peers.append(
                PeerRuntime(
                    public_key=parts[0],
                    preshared_key=parts[1] or ABSENT,
                    endpoint=parts[2] or ABSENT,
                    allowed_ips=[a for a in parts[3].split(",") if a],
                    latest_handshake=to_int(parts[4]) or 0,
                    rx=to_int(parts[5]) or 0,
                    tx=to_int(parts[6]) or 0,
                    persistent_keepalive=to_int(parts[7]) or 0,
                )
            )
    return runtime


def read_interface(interface: str, runner: Runner) -> InterfaceRuntime:
    """Return the live state; ``exists`` is False when the interface is absent."""
    result = runner.exec(["wg", "show", interface, "dump"], timeout=WG_LIST_TIMEOUT)
    runtime = InterfaceRuntime(name=interface)
    if not result.ok or not result.stdout.strip():
        return runtime

    runtime = _parse_dump(result.stdout)
    runtime.name = interface
    runtime.exists = True

    for entry in _ip_json(runner, ["ip", "-j", "addr", "show", "dev", interface]):
        for info in entry.get("addr_info", []) or []:
            local = info.get("local")
            prefix = info.get("prefixlen")
            if local is None or prefix is None:
                continue
            runtime.addresses.append(f"{local}/{prefix}")

    for entry in _ip_json(runner, ["ip", "-j", "link", "show", "dev", interface]):
        runtime.mtu = to_int(entry.get("mtu"))
        runtime.up = entry.get("operstate") == "UP" or "UP" in (entry.get("flags") or [])

    for entry in _ip_json(runner, ["ip", "-j", "route", "show", "dev", interface]):
        dst = entry.get("dst")
        if dst:
            runtime.routes.append(dst)
        else:
            runtime.routes.append("::/0" if entry.get("family") == "inet6" else "0.0.0.0/0")

    return runtime


def snapshot(interface: str, *, runner: Runner, redact: bool = True) -> dict:
    return read_interface(interface, runner).to_dict(redact=redact)


# --------------------------------------------------------------------------- #
# comparisons used by the differ and the verifier
# --------------------------------------------------------------------------- #
def route_covered(cidr: str, routes: Sequence[str]) -> bool:
    """``ip route show dev IF match CIDR`` semantics: is a covering route present?"""
    try:
        candidate = ip_network(cidr, strict=False)
    except ValueError:
        return False
    for route in routes:
        try:
            existing = ip_network(route, strict=False)
        except ValueError:
            continue
        if existing.version == candidate.version and candidate.subnet_of(existing):
            return True
    return False


def desired_addresses(cfg: InterfaceConfig) -> frozenset[str]:
    return frozenset(
        cidr for cidr in (address_cidr(item) for item in cfg.address) if cidr
    )
