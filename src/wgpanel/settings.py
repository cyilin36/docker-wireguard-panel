"""Panel settings that are not part of the tunnel configuration itself.

The client config we hand out needs a server address and an AllowedIPs list; none
of that lives in the server's ``wg0.conf``. They are stored next to the panel
state and defaulted from the LinuxServer ``.donoteditthisfile`` marker when it
exists. The client DNS is the exception: it starts empty and stays empty until an
admin asks for one (see :func:`derive_defaults`).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass

from . import files
from .model import InterfaceConfig, to_int

SETTINGS_NAME = "settings.json"
MARKER_NAME = ".donoteditthisfile"

_MARKER_RE = re.compile(r'^ORIG_([A-Z_]+)="?(.*?)"?$', re.MULTILINE)


@dataclass
class Settings:
    server_url: str = ""
    server_port: int = 51820
    client_dns: str = ""
    client_allowed_ips: str = "0.0.0.0/0, ::/0"
    client_keepalive: int = 25

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def client_ready(self) -> bool:
        return bool(self.server_url.strip())

    def missing(self) -> list[str]:
        return [] if self.client_ready else ["server_url"]


def marker_path(config_dir: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(config_dir.rstrip("/"))), MARKER_NAME)


def read_marker(config_dir: str) -> dict[str, str]:
    path = marker_path(config_dir)
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return {}
    return {match.group(1): match.group(2) for match in _MARKER_RE.finditer(text)}


def derive_defaults(cfg: InterfaceConfig | None, config_dir: str) -> Settings:
    """Defaults for a panel that has never saved its own settings.

    ``client_dns`` is deliberately **not** derived from anywhere: neither from the
    interface address nor from the LinuxServer ``ORIG_PEERDNS`` marker. A guessed
    resolver is worse than none — with the usual ``AllowedIPs = 0.0.0.0/0`` a
    wrong address sends every query into a tunnel where nothing answers, and the
    client loses name resolution entirely. Empty means "leave the client's own DNS
    alone", and the admin can still set one in the panel.
    """
    settings = Settings()
    marker = read_marker(config_dir)

    if cfg is not None:
        settings.server_port = to_int(cfg.listen_port) or 51820

    if marker.get("SERVERURL"):
        settings.server_url = marker["SERVERURL"]
    if to_int(marker.get("SERVERPORT")):
        settings.server_port = to_int(marker["SERVERPORT"]) or settings.server_port
    if marker.get("ALLOWEDIPS"):
        settings.client_allowed_ips = marker["ALLOWEDIPS"]
    return settings


def stored_str(stored: dict, key: str, fallback: str) -> str:
    """A stored value wins even when it is empty.

    ``stored.get(key) or fallback`` resurrects the default the moment a field is
    cleared, so "delete the client DNS and save" silently came back as the
    derived ``ORIG_PEERDNS``/interface address. Only a missing key falls back.
    """
    value = stored.get(key)
    return fallback if value is None else str(value)


def load_settings(state_dir: str, *, defaults: Settings | None = None) -> Settings:
    defaults = defaults or Settings()
    raw = files.read_bytes(os.path.join(state_dir, SETTINGS_NAME))
    stored: dict = {}
    if raw:
        try:
            stored = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            stored = {}

    merged = Settings(
        server_url=stored_str(stored, "server_url", defaults.server_url),
        server_port=to_int(stored.get("server_port")) or defaults.server_port,
        client_dns=stored_str(stored, "client_dns", defaults.client_dns),
        client_allowed_ips=stored_str(stored, "client_allowed_ips", defaults.client_allowed_ips),
        client_keepalive=to_int(stored.get("client_keepalive"))
        if to_int(stored.get("client_keepalive")) is not None
        else defaults.client_keepalive,
    )
    return merged


def save_settings(state_dir: str, settings: Settings) -> Settings:
    files.ensure_dir(state_dir)
    files.atomic_write(
        os.path.join(state_dir, SETTINGS_NAME),
        json.dumps(settings.to_dict(), indent=2).encode("utf-8"),
        mode=0o600,
    )
    return settings
