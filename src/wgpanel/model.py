"""Domain model: parsed wg-quick configuration plus change-plan value types.

Everything here is a plain dataclass so it can be serialised to JSON for the CLI
and, later, for the HTTP API without pulling in a web framework.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from ipaddress import ip_network
from typing import Literal

Mode = Literal["noop", "start", "sync", "sync_addr", "sync_addr_route", "bounce"]
Level = Literal["error", "warning"]
Status = Literal["ok", "warn", "fail"]

REDACTED = "(redacted)"
ABSENT = "(none)"


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def to_int(value: object) -> int | None:
    """Best-effort integer conversion; returns None instead of raising."""
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def split_list(value: str) -> list[str]:
    """Split a comma separated wg-quick value (``Address``, ``DNS``, ``AllowedIPs``)."""
    return [part.strip() for part in value.split(",") if part.strip()]


def normalize_cidr(value: str) -> str | None:
    """Normalise ``10.0.0.1`` / ``10.0.0.0/24`` to a canonical network string."""
    try:
        return str(ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def normalize_cidrs(values: Iterable[str]) -> frozenset[str]:
    out = {normalize_cidr(v) for v in values}
    out.discard(None)
    return frozenset(v for v in out if v is not None)


def address_cidr(value: str) -> str | None:
    """Normalise an ``Address`` token: a bare IP means /32 (v4) or /128 (v6)."""
    token = value.strip()
    if not token:
        return None
    if "/" not in token:
        token = f"{token}/128" if ":" in token else f"{token}/32"
    return normalize_cidr(token)


def is_default_route(cidr: str) -> bool:
    return cidr.endswith("/0")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short_key(public_key: str) -> str:
    key = (public_key or "").strip()
    return key[:12] + "..." if len(key) > 15 else key


def normalize_fwmark(value: str | None) -> str | None:
    """Reduce ``0xca6c`` / ``51820`` / ``off`` to a comparable form."""
    if value is None:
        return None
    token = value.strip().lower()
    if not token or token in ("off", ABSENT):
        return None
    try:
        return str(int(token, 0))
    except ValueError:
        return token


def normalize_endpoint(value: str | None) -> str | None:
    if value is None:
        return None
    token = value.strip().lower()
    if not token or token == ABSENT:
        return None
    return token


def dump_key_present(value: str | None) -> bool:
    """``wg show dump`` prints ``(none)`` for an unset preshared key."""
    return (value or "").strip().lower() not in ("", ABSENT, "off")


# --------------------------------------------------------------------------- #
# configuration model
# --------------------------------------------------------------------------- #
@dataclass
class PeerConfig:
    public_key: str = ""
    preshared_key: str | None = None
    endpoint: str | None = None
    allowed_ips: list[str] = field(default_factory=list)
    persistent_keepalive: str | None = None
    comment: str | None = None
    extra: list[str] = field(default_factory=list)

    @property
    def key_id(self) -> str:
        return short_key(self.public_key)

    def allowed_ip_set(self) -> frozenset[str]:
        return normalize_cidrs(self.allowed_ips)

    def to_lines(self) -> list[str]:
        lines = ["[Peer]"]
        if self.comment:
            lines.append(f"# {self.comment}")
        lines.append(f"PublicKey = {self.public_key}")
        if self.preshared_key is not None:
            lines.append(f"PresharedKey = {self.preshared_key}")
        if self.allowed_ips:
            lines.append("AllowedIPs = " + ",".join(self.allowed_ips))
        if self.endpoint:
            lines.append(f"Endpoint = {self.endpoint}")
        if self.persistent_keepalive is not None:
            lines.append(f"PersistentKeepalive = {self.persistent_keepalive}")
        lines.extend(self.extra)
        return lines


@dataclass
class InterfaceConfig:
    """A parsed ``*.conf`` file.

    Numeric wg-quick fields stay as raw strings so that a malformed value can be
    reported by :mod:`wgpanel.validate` instead of blowing up the parser.
    """

    name: str = ""
    path: str = ""
    address: list[str] = field(default_factory=list)
    listen_port: str | None = None
    private_key: str | None = None
    fwmark: str | None = None
    mtu: str | None = None
    dns: list[str] = field(default_factory=list)
    table: str | None = None
    save_config: str | None = None
    pre_up: list[str] = field(default_factory=list)
    post_up: list[str] = field(default_factory=list)
    pre_down: list[str] = field(default_factory=list)
    post_down: list[str] = field(default_factory=list)
    peers: list[PeerConfig] = field(default_factory=list)
    leading: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    has_interface_section: bool = False

    # -- derived facts ----------------------------------------------------- #
    @property
    def table_mode(self) -> str | None:
        """``None``/``auto`` mean the main table, ``off`` disables routes."""
        return (self.table or "").strip().lower() or None

    @property
    def save_config_enabled(self) -> bool:
        return (self.save_config or "").strip().lower() == "true"

    def peer_by_key(self, public_key: str) -> PeerConfig | None:
        for peer in self.peers:
            if peer.public_key == public_key:
                return peer
        return None

    def allowed_ip_map(self) -> dict[str, frozenset[str]]:
        return {peer.public_key: peer.allowed_ip_set() for peer in self.peers}

    def all_allowed_ips(self) -> frozenset[str]:
        out: set[str] = set()
        for peer in self.peers:
            out |= peer.allowed_ip_set()
        return frozenset(out)

    def hooks(self) -> tuple[Sequence[str], Sequence[str], Sequence[str], Sequence[str]]:
        return (self.pre_up, self.post_up, self.pre_down, self.post_down)

    # -- serialisation ----------------------------------------------------- #
    def to_text(self) -> str:
        lines = list(self.leading)
        lines.append("[Interface]")
        for addr in self.address:
            lines.append(f"Address = {addr}")
        if self.listen_port is not None:
            lines.append(f"ListenPort = {self.listen_port}")
        if self.private_key is not None:
            lines.append(f"PrivateKey = {self.private_key}")
        if self.fwmark is not None:
            lines.append(f"FwMark = {self.fwmark}")
        if self.mtu is not None:
            lines.append(f"MTU = {self.mtu}")
        if self.dns:
            lines.append("DNS = " + ", ".join(self.dns))
        if self.table is not None:
            lines.append(f"Table = {self.table}")
        if self.save_config is not None:
            lines.append(f"SaveConfig = {self.save_config}")
        lines.extend(self.extra)
        for hook in self.pre_up:
            lines.append(f"PreUp = {hook}")
        for hook in self.post_up:
            lines.append(f"PostUp = {hook}")
        for hook in self.pre_down:
            lines.append(f"PreDown = {hook}")
        for hook in self.post_down:
            lines.append(f"PostDown = {hook}")
        for peer in self.peers:
            lines.append("")
            lines.extend(peer.to_lines())
        return "\n".join(lines) + "\n"

    def to_dict(self, *, redact: bool = True) -> dict:
        """JSON-safe view. Private material is redacted by default."""
        data = {
            "name": self.name,
            "path": self.path,
            "address": list(self.address),
            "listen_port": to_int(self.listen_port),
            "listen_port_raw": self.listen_port,
            "fwmark": self.fwmark,
            "mtu": to_int(self.mtu),
            "dns": list(self.dns),
            "table": self.table,
            "save_config": self.save_config,
            "hooks": {
                "pre_up": list(self.pre_up),
                "post_up": list(self.post_up),
                "pre_down": list(self.pre_down),
                "post_down": list(self.post_down),
            },
            "peers": [
                {
                    "public_key": peer.public_key,
                    "key_id": peer.key_id,
                    "comment": peer.comment,
                    "endpoint": peer.endpoint,
                    "allowed_ips": list(peer.allowed_ips),
                    "persistent_keepalive": to_int(peer.persistent_keepalive),
                    "has_preshared_key": peer.preshared_key not in (None, "", "off"),
                }
                for peer in self.peers
            ],
        }
        data["has_private_key"] = self.private_key not in (None, "")
        data["private_key"] = REDACTED if redact else self.private_key
        return data


# --------------------------------------------------------------------------- #
# plan / result value types
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Check:
    """One doctor finding."""

    id: str
    status: Status
    message: str
    hint: str | None = None

    def to_dict(self) -> dict:
        data = {"id": self.id, "status": self.status, "message": self.message}
        if self.hint:
            data["hint"] = self.hint
        return data


@dataclass(frozen=True)
class Issue:
    level: Level
    code: str
    message: str
    where: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Step:
    """One atomic action of a :class:`ChangePlan`.

    ``content`` holds the bytes for a ``write_file`` step and is deliberately
    excluded from :meth:`describe` so a plan can be logged or returned over HTTP
    without leaking private keys.
    """

    kind: Literal["write_file", "exec"]
    why: str
    argv: tuple[str, ...] = ()
    path: str | None = None
    content: bytes | None = None
    retry_on_failure: bool = False

    def describe(self) -> dict:
        if self.kind == "exec":
            data: dict = {"kind": "exec", "why": self.why, "argv": list(self.argv)}
        else:
            payload = self.content or b""
            data = {
                "kind": "write_file",
                "why": self.why,
                "path": self.path,
                "size": len(payload),
                "sha256": sha256_hex(payload)[:16],
            }
        if self.retry_on_failure:
            data["retry_on_failure"] = True
        return data


@dataclass
class PeerChanges:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChangePlan:
    interface: str
    conf_path: str
    state_dir: str
    mode: Mode
    reasons: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    peer_changes: PeerChanges = field(default_factory=PeerChanges)
    changed_fields: list[str] = field(default_factory=list)
    destructive: bool = False
    disruptive: bool = False
    warnings: list[str] = field(default_factory=list)
    expected_revision: str = ""
    desired_sha256: str = ""

    @property
    def exec_steps(self) -> list[Step]:
        return [step for step in self.steps if step.kind == "exec"]

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "conf_path": self.conf_path,
            "mode": self.mode,
            "reasons": list(self.reasons),
            "changed_fields": list(self.changed_fields),
            "peer_changes": self.peer_changes.to_dict(),
            "destructive": self.destructive,
            "disruptive": self.disruptive,
            "warnings": list(self.warnings),
            "expected_revision": self.expected_revision,
            "desired_sha256": self.desired_sha256,
            "steps": [step.describe() for step in self.steps],
        }


@dataclass(frozen=True)
class FieldDiff:
    field: str
    expected: str
    actual: str
    ok: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ApplyResult:
    ok: bool
    interface: str
    mode: str
    steps_run: int = 0
    exec_count: int = 0
    file_revision: str = ""
    history_entry: str | None = None
    rolled_back: bool = False
    critical: bool = False
    verify: list[FieldDiff] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    manual_commands: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verify"] = [d.to_dict() for d in self.verify]
        return data
