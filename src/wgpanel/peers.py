"""Peer lifecycle: create, edit, delete, export client configs and QR codes.

The ``*.conf`` file stays the single source of truth for *who* the peers are; the
panel only owns the extra material a client needs (its private key, its
preshared key) which it keeps under ``<state-dir>/peers/<name>/``.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import Protocol

from . import files, qr
from .apply import apply
from .differ import Target
from .errors import WgPanelError
from .model import (
    ApplyResult,
    InterfaceConfig,
    PeerConfig,
    address_cidr,
    normalize_cidr,
    to_int,
)
from .parse import parse_bytes
from .runner import LocalRunner, Runner
from .runtime import InterfaceRuntime, read_interface
from .settings import Settings, derive_defaults, load_settings, save_settings

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
ONLINE_WINDOW = 180  # seconds since the last handshake
UNSET = object()


def sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "-", (value or "").strip()).strip("-.")
    return cleaned[:32] or "peer"


def peer_name(peer: PeerConfig, index: int) -> str:
    """Names live in the comment above ``PublicKey``.

    LinuxServer writes ``# peer1``; wireguard-ui and others write
    ``# friendly_name = laptop``. Both are understood.
    """
    comment = (peer.comment or "").strip()
    if not comment:
        return f"peer{index}"
    if "=" in comment:
        key, _, value = comment.partition("=")
        if key.strip().lower() in {"friendly_name", "name", "peer", "id", "comment"}:
            return sanitize_name(value)
    return sanitize_name(comment)


def tunnel_networks(cfg: InterfaceConfig) -> list:
    """The tunnel subnet(s). A bare address is read as /24 or /64."""
    networks = []
    for token in cfg.address:
        text = token.strip()
        if not text:
            continue
        if "/" not in text:
            text = f"{text}/64" if ":" in text else f"{text}/24"
        normalized = normalize_cidr(text)
        if normalized:
            networks.append(ip_network(normalized, strict=False))
    return networks


def used_addresses(cfg: InterfaceConfig) -> set[str]:
    used = set()
    for peer in cfg.peers:
        for cidr in peer.allowed_ips:
            normalized = address_cidr(cidr)
            if normalized:
                used.add(normalized)
    for token in cfg.address:
        normalized = address_cidr(token)
        if normalized:
            used.add(normalized)
    return used


def allocate_address(cfg: InterfaceConfig, *, version: int = 4) -> str:
    networks = [net for net in tunnel_networks(cfg) if net.version == version]
    if not networks:
        raise WgPanelError(
            f"cannot allocate an address: {cfg.path} has no IPv{version} Address to derive "
            "a tunnel subnet from"
        )
    network = networks[0]
    used = used_addresses(cfg)
    for host in network.hosts():
        candidate = f"{host}/{32 if version == 4 else 128}"
        if candidate not in used:
            return str(host)
    raise WgPanelError(f"no free address left in {network}")


def host_address(value: str) -> str | None:
    """Normalise a peer's own tunnel address: ``10.13.13.5`` -> ``10.13.13.5/32``.

    Only a single host is accepted. The peer's own address is what ends up in the
    client's ``Address``, so a wider prefix belongs in the extra AllowedIPs list
    instead — accepting one here would make the exported config invalid.
    """
    normalized = address_cidr(value)
    if normalized is None:
        return None
    return normalized if normalized.rpartition("/")[2] in ("32", "128") else None


class KeySource(Protocol):
    def genkey(self) -> str:
        ...

    def pubkey(self, private_key: str) -> str:
        ...

    def genpsk(self) -> str:
        ...


class WgKeySource:
    """Key generation through the ``wg`` binary."""

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def _run(self, argv: Sequence[str], stdin: bytes | None = None) -> str:
        result = self.runner.exec(list(argv), stdin=stdin, timeout=15.0)
        if not result.ok or not result.stdout.strip():
            raise WgPanelError(f"{' '.join(argv)} failed: {result.stderr.strip() or result.exit_code}")
        return result.stdout.strip()

    def genkey(self) -> str:
        return self._run(["wg", "genkey"])

    def pubkey(self, private_key: str) -> str:
        return self._run(["wg", "pubkey"], stdin=(private_key.strip() + "\n").encode())

    def genpsk(self) -> str:
        return self._run(["wg", "genpsk"])


@dataclass
class PeerView:
    name: str
    public_key: str
    allowed_ips: list[str] = field(default_factory=list)
    endpoint: str | None = None
    config_endpoint: str | None = None
    persistent_keepalive: int | None = None
    has_preshared_key: bool = False
    client_ip: str | None = None
    has_keys: bool = False
    online: bool = False
    latest_handshake: int = 0
    rx: int = 0
    tx: int = 0
    rx_rate: float = 0.0
    tx_rate: float = 0.0

    @property
    def key_id(self) -> str:
        return self.public_key[:12] + "..." if len(self.public_key) > 15 else self.public_key

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "public_key": self.public_key,
            "key_id": self.key_id,
            "allowed_ips": list(self.allowed_ips),
            "endpoint": self.endpoint,
            "config_endpoint": self.config_endpoint,
            "persistent_keepalive": self.persistent_keepalive,
            "has_preshared_key": self.has_preshared_key,
            "client_ip": self.client_ip,
            "has_keys": self.has_keys,
            "online": self.online,
            "latest_handshake": self.latest_handshake,
            "rx": self.rx,
            "tx": self.tx,
            "rx_rate": round(self.rx_rate, 1),
            "tx_rate": round(self.tx_rate, 1),
        }


class PeerManager:
    def __init__(
        self,
        target: Target,
        *,
        runner: Runner | None = None,
        keys: KeySource | None = None,
        config_dir: str = "",
        clock=time.time,
        monotonic=time.monotonic,
    ) -> None:
        self.target = target
        self.runner = runner or LocalRunner()
        self.keys = keys or WgKeySource(self.runner)
        self.config_dir = config_dir or os.path.dirname(os.path.abspath(target.conf_path))
        self._clock = clock
        self._monotonic = monotonic
        self._rates: dict[str, tuple[float, int, int, float, float]] = {}

    # ------------------------------------------------------------------ #
    # config / settings plumbing
    # ------------------------------------------------------------------ #
    def config(self) -> InterfaceConfig:
        raw = files.read_bytes(self.target.conf_path)
        if not raw:
            raise WgPanelError(f"{self.target.conf_path} does not exist")
        return parse_bytes(raw, path=self.target.conf_path)

    def settings(self) -> Settings:
        try:
            cfg = self.config()
        except WgPanelError:
            cfg = None
        return load_settings(
            self.target.state_dir,
            defaults=derive_defaults(cfg, self.config_dir),
        )

    def update_settings(self, payload: dict) -> Settings:
        current = self.settings()
        merged = Settings(
            server_url=str(payload.get("server_url", current.server_url) or "").strip(),
            server_port=to_int(payload.get("server_port")) or current.server_port,
            client_dns=str(payload.get("client_dns", current.client_dns) or "").strip(),
            client_allowed_ips=str(
                payload.get("client_allowed_ips", current.client_allowed_ips) or ""
            ).strip()
            or current.client_allowed_ips,
            client_keepalive=to_int(payload.get("client_keepalive"))
            if payload.get("client_keepalive") is not None
            else current.client_keepalive,
        )
        return save_settings(self.target.state_dir, merged)

    # ------------------------------------------------------------------ #
    # keys on disk
    # ------------------------------------------------------------------ #
    def key_dir(self, name: str) -> str:
        path = os.path.join(self.target.state_dir, "peers", sanitize_name(name))
        files.assert_within(self.target.state_dir, path)
        return path

    def has_keys(self, name: str) -> bool:
        return os.path.isfile(os.path.join(self.key_dir(name), "privatekey"))

    def read_private_key(self, name: str) -> str:
        raw = files.read_bytes(os.path.join(self.key_dir(name), "privatekey"))
        if not raw:
            raise WgPanelError(f"no stored private key for peer {name!r}")
        return raw.decode("utf-8").strip()

    def _store_keys(self, name: str, private: str, public: str, preshared: str) -> None:
        directory = files.ensure_dir(self.key_dir(name))
        for filename, value in (
            ("privatekey", private),
            ("publickey", public),
            ("presharedkey", preshared),
        ):
            files.atomic_write(os.path.join(directory, filename), (value + "\n").encode(), mode=0o600)

    def _rename_keys(self, old: str, new: str) -> None:
        source, destination = self.key_dir(old), self.key_dir(new)
        if old != new and os.path.isdir(source) and not os.path.exists(destination):
            os.rename(source, destination)

    # ------------------------------------------------------------------ #
    # lookups
    # ------------------------------------------------------------------ #
    def find(
        self, reference: str, cfg: InterfaceConfig | None = None
    ) -> tuple[int, PeerConfig, str]:
        cfg = cfg if cfg is not None else self.config()
        wanted = (reference or "").strip()
        for index, peer in enumerate(cfg.peers):
            if peer.public_key == wanted:
                return index, peer, peer_name(peer, index + 1)
        for index, peer in enumerate(cfg.peers):
            if peer_name(peer, index + 1).lower() == wanted.lower():
                return index, peer, peer_name(peer, index + 1)
        raise WgPanelError(f"no peer matches {reference!r}")

    # ------------------------------------------------------------------ #
    # read views
    # ------------------------------------------------------------------ #
    def views(self, runtime: InterfaceRuntime | None = None) -> list[PeerView]:
        cfg = self.config()
        if runtime is None:
            runtime = read_interface(self.target.interface, self.runner)
        now = self._monotonic()
        wall = self._clock()

        views: list[PeerView] = []
        for index, peer in enumerate(cfg.peers, start=1):
            name = peer_name(peer, index)
            live = runtime.peer_by_key(peer.public_key) if runtime.exists else None
            rx = live.rx if live else 0
            tx = live.tx if live else 0

            rate_rx = rate_tx = 0.0
            previous = self._rates.get(peer.public_key)
            if previous is not None:
                elapsed = now - previous[0]
                if elapsed >= 0.5:
                    if rx >= previous[1]:
                        rate_rx = (rx - previous[1]) / elapsed
                    if tx >= previous[2]:
                        rate_tx = (tx - previous[2]) / elapsed
                else:
                    rate_rx, rate_tx = previous[3], previous[4]
            self._rates[peer.public_key] = (now, rx, tx, rate_rx, rate_tx)

            handshake = live.latest_handshake if live else 0
            client_ip = None
            for cidr in peer.allowed_ips:
                normalized = address_cidr(cidr)
                if normalized and normalized.endswith(("/32", "/128")):
                    client_ip = normalized.split("/")[0]
                    break

            views.append(
                PeerView(
                    name=name,
                    public_key=peer.public_key,
                    allowed_ips=list(peer.allowed_ips),
                    endpoint=None if (live is None or live.endpoint == "(none)") else live.endpoint,
                    config_endpoint=peer.endpoint,
                    persistent_keepalive=to_int(peer.persistent_keepalive),
                    has_preshared_key=peer.preshared_key not in (None, "", "off"),
                    client_ip=client_ip,
                    has_keys=self.has_keys(name),
                    online=bool(handshake) and (wall - handshake) < ONLINE_WINDOW,
                    latest_handshake=handshake,
                    rx=rx,
                    tx=tx,
                    rx_rate=rate_rx,
                    tx_rate=rate_tx,
                )
            )
        return views

    # ------------------------------------------------------------------ #
    # writes
    # ------------------------------------------------------------------ #
    def _commit(
        self,
        cfg: InterfaceConfig,
        *,
        apply_now: bool,
        allow_disruptive: bool = False,
        allow_destructive: bool = False,
    ) -> ApplyResult | None:
        data = cfg.to_text().encode("utf-8")
        if not apply_now:
            files.atomic_write(self.target.conf_path, data)
            return None
        return apply(
            self.target,
            data,
            runner=self.runner,
            allow_disruptive=allow_disruptive,
            allow_destructive=allow_destructive,
        )

    def _own_address(self, cfg: InterfaceConfig, requested: str | None) -> str:
        """The peer's own AllowedIPs entry.

        An empty request keeps the historical behaviour (the next free host of the
        tunnel subnet); anything else is taken literally so the caller can pin the
        address it wants instead of inheriting the sequential one.
        """
        wanted = str(requested or "").strip()
        if not wanted:
            return f"{allocate_address(cfg)}/32"
        chosen = host_address(wanted)
        if chosen is None:
            raise WgPanelError(
                f"{wanted!r} is not a single host address (use 10.13.13.5 or 10.13.13.5/32; "
                "a wider range belongs in the extra allowed networks)"
            )
        if chosen in used_addresses(cfg):
            raise WgPanelError(f"{chosen} is already used by the interface or another peer")
        return chosen

    def add(
        self,
        name: str,
        *,
        address: str | None = None,
        keepalive: int | None = None,
        extra_allowed_ips: Iterable[str] = (),
        apply_now: bool = True,
    ) -> tuple[PeerView, ApplyResult | None]:
        candidate = (name or "").strip()
        if not NAME_RE.match(candidate):
            raise WgPanelError(
                "peer name must be 1-32 characters of letters, digits, dot, dash or underscore"
            )
        cfg = self.config()
        existing = {peer_name(peer, index + 1).lower() for index, peer in enumerate(cfg.peers)}
        if candidate.lower() in existing:
            raise WgPanelError(f"a peer named {candidate!r} already exists")

        own = self._own_address(cfg, address)
        private = self.keys.genkey()
        public = self.keys.pubkey(private)
        preshared = self.keys.genpsk()
        self._store_keys(candidate, private, public, preshared)

        allowed = [own]
        for extra in extra_allowed_ips:
            normalized = normalize_cidr(str(extra))
            if not normalized:
                raise WgPanelError(f"{extra!r} is not a valid CIDR")
            if normalized not in allowed:
                allowed.append(normalized)

        cfg.peers.append(
            PeerConfig(
                public_key=public,
                preshared_key=preshared,
                allowed_ips=allowed,
                comment=candidate,
                persistent_keepalive=str(keepalive) if keepalive else None,
            )
        )
        result = self._commit(cfg, apply_now=apply_now)
        view = next(v for v in self.views() if v.public_key == public)
        return view, result

    def update(
        self,
        reference: str,
        *,
        name: str | None = None,
        allowed_ips: Sequence[str] | None = None,
        keepalive: object = UNSET,
        endpoint: object = UNSET,
        apply_now: bool = True,
    ) -> tuple[PeerView, ApplyResult | None]:
        cfg = self.config()
        index, peer, current_name = self.find(reference, cfg)

        if name is not None and name.strip() and name.strip() != current_name:
            candidate = name.strip()
            if not NAME_RE.match(candidate):
                raise WgPanelError(
                    "peer name must be 1-32 characters of letters, digits, dot, dash or underscore"
                )
            taken = {
                peer_name(other, i + 1).lower()
                for i, other in enumerate(cfg.peers)
                if i != index
            }
            if candidate.lower() in taken:
                raise WgPanelError(f"a peer named {candidate!r} already exists")
            self._rename_keys(current_name, candidate)
            peer.comment = candidate

        if allowed_ips is not None:
            normalized = []
            for cidr in allowed_ips:
                value = normalize_cidr(str(cidr))
                if not value:
                    raise WgPanelError(f"{cidr!r} is not a valid CIDR")
                normalized.append(value)
            if not normalized:
                raise WgPanelError("a peer needs at least one AllowedIPs entry")
            peer.allowed_ips = normalized

        if keepalive is not UNSET:
            value = to_int(keepalive)
            peer.persistent_keepalive = str(value) if value else None

        if endpoint is not UNSET:
            text = str(endpoint or "").strip()
            peer.endpoint = text or None

        result = self._commit(cfg, apply_now=apply_now)
        view = next(v for v in self.views() if v.public_key == peer.public_key)
        return view, result

    def remove(self, reference: str, *, apply_now: bool = True) -> ApplyResult | None:
        cfg = self.config()
        index, _peer, name = self.find(reference, cfg)
        cfg.peers.pop(index)
        result = self._commit(cfg, apply_now=apply_now, allow_destructive=True)
        shutil.rmtree(self.key_dir(name), ignore_errors=True)
        return result

    # ------------------------------------------------------------------ #
    # client export
    # ------------------------------------------------------------------ #
    def server_public_key(self) -> str:
        result = self.runner.exec(["wg", "show", self.target.interface, "public-key"], timeout=10.0)
        if result.ok and result.stdout.strip():
            return result.stdout.strip()
        cfg = self.config()
        if cfg.private_key:
            derived = self.runner.exec(
                ["wg", "pubkey"], stdin=(cfg.private_key.strip() + "\n").encode(), timeout=10.0
            )
            if derived.ok and derived.stdout.strip():
                return derived.stdout.strip()
        raise WgPanelError("cannot determine the server public key (is the interface up?)")

    def client_conf(self, reference: str) -> str:
        _, peer, name = self.find(reference)
        settings = self.settings()
        if not settings.client_ready:
            raise WgPanelError(
                "set the server address in the panel settings before exporting a client config"
            )
        private = self.read_private_key(name)

        address = None
        for cidr in peer.allowed_ips:
            normalized = address_cidr(cidr)
            if normalized and normalized.endswith(("/32", "/128")):
                address = normalized
                break
        if address is None:
            raise WgPanelError(f"peer {name!r} has no single-host AllowedIPs to use as its address")

        lines = [
            "[Interface]",
            f"Address = {address}",
            f"PrivateKey = {private}",
        ]
        if settings.client_dns:
            lines.append(f"DNS = {settings.client_dns}")
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {self.server_public_key()}",
        ]
        if peer.preshared_key and peer.preshared_key != "off":
            lines.append(f"PresharedKey = {peer.preshared_key}")
        lines.append(f"Endpoint = {settings.server_url.strip()}:{settings.server_port}")
        lines.append(f"AllowedIPs = {settings.client_allowed_ips}")
        if settings.client_keepalive:
            lines.append(f"PersistentKeepalive = {settings.client_keepalive}")
        return "\n".join(lines) + "\n"

    def client_qr_svg(self, reference: str) -> str:
        return qr.svg(self.client_conf(reference))

    def client_qr_png(self, reference: str) -> bytes:
        return qr.png(self.client_conf(reference))
