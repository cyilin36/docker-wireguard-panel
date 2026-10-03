"""Validation of a parsed configuration.

Rules follow what ``wg-quick`` and the LinuxServer entrypoint actually require,
plus the failure modes we hit in practice (see README).
"""

from __future__ import annotations

import base64
import binascii
import re

from .model import ABSENT, InterfaceConfig, Issue, address_cidr, normalize_cidr, to_int

CONF_BASENAME_RE = re.compile(r"^[a-zA-Z0-9_=+.-]{1,15}\.conf$")
ENDPOINT_RE = re.compile(r"^(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):(?P<port>\d{1,5})$")
SHELLISH = ("$(", "`")

#: wg-quick does not eval values, and hooks are the only fields it does eval.
SCALAR_FIELDS = (
    "private_key",
    "listen_port",
    "fwmark",
    "mtu",
    "table",
    "dns",
    "address",
)
PEER_SCALAR_FIELDS = (
    "public_key",
    "preshared_key",
    "endpoint",
    "allowed_ips",
    "persistent_keepalive",
)


def is_wg_key(value: str) -> bool:
    token = (value or "").strip()
    if token == "off":
        return True
    if len(token) != 44 or not token.endswith("="):
        return False
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def _flatten(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return [str(value)]


def _shellish_issues(cfg: InterfaceConfig) -> list[Issue]:
    issues: list[Issue] = []

    def check(where: str, field: str, value: object) -> None:
        for token in _flatten(value):
            if any(marker in token for marker in SHELLISH):
                issues.append(
                    Issue(
                        "error",
                        "value_not_evaluated",
                        f"{field} contains a shell substitution ({token!r}); wg-quick does not "
                        "expand values, so wg(8) would receive it literally and fail. Write the "
                        "expanded key instead (the LinuxServer template files use $(cat ...) but "
                        "the generated wg0.conf never does).",
                        where,
                    )
                )

    for field in SCALAR_FIELDS:
        check("[Interface]", field, getattr(cfg, field))
    for index, peer in enumerate(cfg.peers, start=1):
        for field in PEER_SCALAR_FIELDS:
            check(f"[Peer] #{index}", field, getattr(peer, field))
    return issues


def validate(cfg: InterfaceConfig) -> list[Issue]:
    issues: list[Issue] = []

    def err(code: str, message: str, where: str | None = None) -> None:
        issues.append(Issue("error", code, message, where))

    def warn(code: str, message: str, where: str | None = None) -> None:
        issues.append(Issue("warning", code, message, where))

    # -- file name ---------------------------------------------------------
    if cfg.path:
        basename = cfg.path.rsplit("/", 1)[-1]
        if not CONF_BASENAME_RE.match(basename):
            err(
                "bad_filename",
                f"file name {basename!r} is not a valid wg-quick interface config name; "
                "it must match [A-Za-z0-9_=+.-]{1,15}.conf (the name becomes the interface name)",
            )

    # -- interface section -------------------------------------------------
    if not cfg.has_interface_section:
        err("missing_interface_section", "no [Interface] section found")
        return issues

    if not cfg.private_key:
        err("missing_private_key", "[Interface] has no PrivateKey")
    elif not is_wg_key(cfg.private_key):
        err("bad_private_key", "PrivateKey is not a 44 character base64 wireguard key")

    listen_port = to_int(cfg.listen_port)
    if cfg.listen_port is not None and listen_port is None:
        err("bad_listen_port", f"ListenPort {cfg.listen_port!r} is not an integer")
    elif listen_port is not None and not 1 <= listen_port <= 65535:
        err("bad_listen_port", f"ListenPort {listen_port} is outside 1-65535")

    fwmark = (cfg.fwmark or "").strip().lower()
    if fwmark and fwmark not in ("off", ABSENT):
        try:
            int(fwmark, 0)
        except ValueError:
            err("bad_fwmark", f"FwMark {cfg.fwmark!r} is neither an integer nor 'off'")

    if cfg.mtu is not None:
        mtu = to_int(cfg.mtu)
        if mtu is None:
            err("bad_mtu", f"MTU {cfg.mtu!r} is not an integer")
        elif not 576 <= mtu <= 65535:
            err("bad_mtu", f"MTU {mtu} is outside 576-65535")

    for addr in cfg.address:
        if address_cidr(addr) is None:
            err("bad_address", f"Address {addr!r} is not an IP address or CIDR")

    for server in cfg.dns:
        if any(marker in server for marker in SHELLISH):
            continue
        if not re.match(r"^[A-Za-z0-9_.:-]+$", server):
            err("bad_dns", f"DNS entry {server!r} does not look like an address or search domain")

    table = cfg.table_mode
    if table not in (None, "auto", "off"):
        try:
            int(table, 0)
        except ValueError:
            err("bad_table", f"Table {cfg.table!r} must be 'auto', 'off' or a table number")

    if cfg.save_config is not None and cfg.save_config.strip().lower() not in ("true", "false"):
        err("bad_save_config", f"SaveConfig {cfg.save_config!r} must be 'true' or 'false'")
    elif cfg.save_config_enabled:
        warn(
            "save_config_enabled",
            "SaveConfig = true: wg-quick down rewrites this file from the live interface, "
            "which can clobber panel edits",
        )

    # -- peers -------------------------------------------------------------
    seen_keys: dict[str, int] = {}
    for index, peer in enumerate(cfg.peers, start=1):
        where = f"[Peer] #{index}"
        if not peer.public_key:
            err("missing_public_key", "peer has no PublicKey", where)
        elif not is_wg_key(peer.public_key):
            err("bad_public_key", f"PublicKey {peer.public_key[:16]!r}... is not a wireguard key", where)
        else:
            seen_keys[peer.public_key] = seen_keys.get(peer.public_key, 0) + 1

        if peer.preshared_key is not None and not is_wg_key(peer.preshared_key):
            err("bad_preshared_key", "PresharedKey is not a wireguard key (or 'off')", where)

        for cidr in peer.allowed_ips:
            if address_cidr(cidr) is None:
                err("bad_allowed_ips", f"AllowedIPs entry {cidr!r} is not a CIDR", where)

        if not peer.allowed_ips:
            warn("empty_allowed_ips", "peer has no AllowedIPs; no traffic will route to it", where)

        if peer.endpoint:
            match = ENDPOINT_RE.match(peer.endpoint.strip())
            if not match:
                err("bad_endpoint", f"Endpoint {peer.endpoint!r} is not host:port", where)
            else:
                port = int(match.group("port"))
                if not 1 <= port <= 65535:
                    err("bad_endpoint", f"Endpoint port {port} is outside 1-65535", where)

        keepalive = to_int(peer.persistent_keepalive)
        if peer.persistent_keepalive is not None:
            if keepalive is None:
                err(
                    "bad_keepalive",
                    f"PersistentKeepalive {peer.persistent_keepalive!r} is not an integer",
                    where,
                )
            elif not 0 <= keepalive <= 65535:
                err("bad_keepalive", f"PersistentKeepalive {keepalive} is outside 0-65535", where)

    for key, count in seen_keys.items():
        if count > 1:
            err("duplicate_public_key", f"PublicKey {key[:16]}... is defined {count} times")

    issues.extend(_overlap_issues(cfg))
    issues.extend(_shellish_issues(cfg))
    return issues


def _overlap_issues(cfg: InterfaceConfig) -> list[Issue]:
    from ipaddress import ip_network

    issues: list[Issue] = []
    ranges: list[tuple[str, object]] = []
    for index, peer in enumerate(cfg.peers, start=1):
        for cidr in peer.allowed_ips:
            normalized = address_cidr(cidr)
            if normalized is None:
                continue
            try:
                ranges.append((f"[Peer] #{index}", ip_network(normalized)))
            except ValueError:  # pragma: no cover - already validated
                continue

    seen: set[str] = set()
    for i, (where_a, net_a) in enumerate(ranges):
        for where_b, net_b in ranges[i + 1:]:
            if net_a.version != net_b.version:
                continue
            if not (net_a.overlaps(net_b)):
                continue
            pair = f"{net_a}|{net_b}"
            if pair in seen:
                continue
            seen.add(pair)
            issues.append(
                Issue(
                    "warning",
                    "allowed_ips_overlap",
                    f"{net_a} and {net_b} overlap; the kernel routes by longest prefix and the "
                    "resulting peer selection is easy to get wrong",
                    where_a if where_a != where_b else f"{where_a} / {where_b}",
                )
            )
    return issues


def subnet_warnings(cfg: InterfaceConfig) -> list[Issue]:
    """Warn when a peer's AllowedIPs falls outside the tunnel subnet.

    A bare ``Address`` (``10.13.13.1``, which the kernel treats as /32) is read as
    the surrounding /24 or /64, because that is what the LinuxServer template
    means by it; an explicit prefix is honoured as written.
    """
    from ipaddress import ip_network

    issues: list[Issue] = []
    subnets = []
    for addr in cfg.address:
        token = addr.strip()
        if "/" not in token:
            token = f"{token}/64" if ":" in token else f"{token}/24"
        normalized = normalize_cidr(token)
        if normalized is None:
            continue
        try:
            subnets.append(ip_network(normalized, strict=False))
        except ValueError:  # pragma: no cover
            continue
    if not subnets:
        return issues
    for index, peer in enumerate(cfg.peers, start=1):
        for cidr in peer.allowed_ips:
            normalized = address_cidr(cidr)
            if normalized is None:
                continue
            net = ip_network(normalized, strict=False)
            if any(net.version == s.version and net.subnet_of(s) for s in subnets):
                continue
            issues.append(
                Issue(
                    "warning",
                    "allowed_ips_outside_subnet",
                    f"{net} is not inside the tunnel subnet "
                    f"({', '.join(str(s) for s in subnets)}); fine for a routed subnet, "
                    "suspicious otherwise",
                    f"[Peer] #{index}",
                )
            )
    return issues


def has_errors(issues: list[Issue]) -> bool:
    return any(issue.level == "error" for issue in issues)


def errors(issues: list[Issue]) -> list[Issue]:
    return [i for i in issues if i.level == "error"]


def warnings(issues: list[Issue]) -> list[Issue]:
    return [i for i in issues if i.level == "warning"]
