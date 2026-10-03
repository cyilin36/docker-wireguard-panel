"""Turn "this file should be live" into an ordered, reviewable plan.

The classification table lives in :func:`decide_mode`; the README documents the
reasoning and the upstream ``wg-quick`` behaviour each branch mirrors.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import files
from .errors import ValidationError
from .model import (
    ChangePlan,
    InterfaceConfig,
    PeerChanges,
    PeerConfig,
    Step,
    address_cidr,
    dump_key_present,
    is_default_route,
    normalize_cidr,
    normalize_endpoint,
    normalize_fwmark,
    sha256_hex,
    short_key,
    to_int,
)
from .parse import parse_bytes
from .runner import LocalRunner, Runner
from .runtime import InterfaceRuntime, PeerRuntime, read_interface, route_covered
from .validate import has_errors, subnet_warnings, validate

#: wg-quick strip removes the directives wg(8) does not understand; the result is
#: fed to `wg syncconf`, which merges only what actually differs and therefore
#: does not disturb established peer sessions.
SYNC_SCRIPT = (
    "set -eo pipefail; "
    "t=$(mktemp) || exit 1; "
    "trap 'rm -f \"$t\"' EXIT; "
    "wg-quick strip \"$1\" >\"$t\" || exit 1; "
    "wg syncconf \"$2\" \"$t\""
)

FILE_LEVEL_FIELDS = {"table", "dns", "hooks", "save_config", "address", "mtu", "allowed_ips"}


@dataclass(frozen=True)
class Target:
    interface: str
    conf_path: str
    state_dir: str = files.DEFAULT_STATE_DIR


# --------------------------------------------------------------------------- #
# individual comparisons
# --------------------------------------------------------------------------- #
def _normalized_addresses(cfg: InterfaceConfig | None) -> frozenset[str]:
    if cfg is None:
        return frozenset()
    return frozenset(cidr for cidr in (address_cidr(a) for a in cfg.address) if cidr)


def _file_level_changes(previous: InterfaceConfig | None, desired: InterfaceConfig) -> set[str]:
    if previous is None:
        return set()
    changed: set[str] = set()
    if (previous.table_mode or None) != (desired.table_mode or None):
        changed.add("table")
    if previous.dns != desired.dns:
        changed.add("dns")
    if tuple(tuple(h) for h in previous.hooks()) != tuple(tuple(h) for h in desired.hooks()):
        changed.add("hooks")
    if (previous.save_config or "").strip().lower() != (desired.save_config or "").strip().lower():
        changed.add("save_config")
    if _normalized_addresses(previous) != _normalized_addresses(desired):
        changed.add("address")
    if to_int(previous.mtu) != to_int(desired.mtu):
        changed.add("mtu")
    if previous.allowed_ip_map() != desired.allowed_ip_map():
        changed.add("allowed_ips")
    return changed


def _peer_differs(
    desired: PeerConfig, live: PeerRuntime, previous: PeerConfig | None = None
) -> bool:
    if desired.allowed_ip_set() != live.allowed_ip_set():
        return True
    want_endpoint = normalize_endpoint(desired.endpoint) if desired.endpoint is not None else None
    if want_endpoint is not None:
        # The live endpoint is *learned* state, not configuration: the kernel
        # rewrites it with the source address of every authenticated packet, so
        # any peer behind NAT (or roaming) drifts away from whatever the file
        # seeded. Only a seed that differs from the last applied file is a real
        # change; the drift alone is not, and re-syncing it would be pointless.
        seeded = normalize_endpoint(previous.endpoint) if previous is not None else None
        if want_endpoint != seeded and want_endpoint != normalize_endpoint(live.endpoint):
            return True
    keepalive = to_int(desired.persistent_keepalive)
    if keepalive is not None and keepalive != live.persistent_keepalive:
        return True
    if desired.preshared_key is not None:
        want_present = desired.preshared_key.strip().lower() != "off"
        if want_present != dump_key_present(live.preshared_key):
            return True
    return False


def _kernel_level_changes(
    runtime: InterfaceRuntime, desired: InterfaceConfig, previous: InterfaceConfig | None = None
) -> tuple[set[str], PeerChanges]:
    changed: set[str] = set()
    peers = PeerChanges()

    if desired.private_key and desired.private_key != runtime.private_key:
        changed.add("private_key")
    listen_port = to_int(desired.listen_port)
    if listen_port is not None and listen_port != runtime.listen_port:
        changed.add("listen_port")
    if desired.fwmark is not None and normalize_fwmark(desired.fwmark) != normalize_fwmark(runtime.fwmark):
        changed.add("fwmark")

    live = {peer.public_key: peer for peer in runtime.peers}
    want = {peer.public_key: peer for peer in desired.peers}
    was = {peer.public_key: peer for peer in previous.peers} if previous is not None else {}
    for key, peer in want.items():
        if key not in live:
            peers.added.append(short_key(key))
        elif _peer_differs(peer, live[key], was.get(key)):
            peers.changed.append(short_key(key))
    for key in live:
        if key not in want:
            peers.removed.append(short_key(key))

    if peers:
        changed.add("peers")
    return changed, peers


def _default_route_change(previous: InterfaceConfig | None, desired: InterfaceConfig) -> bool:
    old = previous.all_allowed_ips() if previous is not None else frozenset()
    new = desired.all_allowed_ips()
    return any(is_default_route(cidr) for cidr in old ^ new)


def _routes_managed(cfg: InterfaceConfig | None) -> bool:
    return cfg is None or cfg.table_mode in (None, "auto")


def decide_mode(
    file_changed: set[str],
    kernel_changed: set[str],
    previous: InterfaceConfig | None,
    desired: InterfaceConfig,
) -> str:
    """The classification table. First match wins."""
    if not file_changed and not kernel_changed:
        return "noop"
    if file_changed & {"table", "dns", "hooks", "save_config"}:
        return "bounce"
    if "allowed_ips" in file_changed:
        if _default_route_change(previous, desired):
            # wg-quick's add_default() installs fwmark + ip rules + nft/iptables
            # counters; reimplementing that live is not worth the risk.
            return "bounce"
        if desired.table_mode == "off" and (previous is None or previous.table_mode == "off"):
            return "sync"
        if _routes_managed(desired) and _routes_managed(previous):
            return "sync_addr_route"
        return "bounce"
    if file_changed & {"address", "mtu"}:
        return "sync_addr"
    if kernel_changed:
        return "sync"
    return "noop"


# --------------------------------------------------------------------------- #
# step builders
# --------------------------------------------------------------------------- #
def sync_step(conf_path: str, interface: str) -> Step:
    return Step(
        kind="exec",
        why="wg syncconf: apply peers/keys/port without disrupting existing sessions",
        argv=("bash", "-c", SYNC_SCRIPT, "wgpanel-sync", conf_path, interface),
    )


def _addr_argv(action: str, address: str, interface: str) -> tuple[str, ...]:
    proto = "-6" if ":" in address else "-4"
    return ("ip", proto, "addr", action, address, "dev", interface)


def _route_argv(action: str, cidr: str, interface: str) -> tuple[str, ...]:
    proto = "-6" if ":" in cidr else "-4"
    return ("ip", proto, "route", action, cidr, "dev", interface)


def _address_steps(
    runtime: InterfaceRuntime,
    previous: InterfaceConfig | None,
    desired: InterfaceConfig,
    interface: str,
) -> list[Step]:
    steps: list[Step] = []
    raw_by_cidr = {}
    for token in desired.address:
        cidr = address_cidr(token)
        if cidr:
            raw_by_cidr[cidr] = token

    have = {cidr for cidr in (normalize_cidr(a) for a in runtime.addresses) if cidr}
    want = set(raw_by_cidr)

    for cidr in sorted(want - have):
        steps.append(
            Step(
                kind="exec",
                why=f"add interface address {cidr} (before removing stale ones)",
                argv=_addr_argv("add", raw_by_cidr[cidr], interface),
            )
        )
    # Only ever remove addresses the previous configuration owned.
    for cidr in sorted((_normalized_addresses(previous) - want) & have):
        steps.append(
            Step(
                kind="exec",
                why=f"remove interface address {cidr} no longer in the configuration",
                argv=_addr_argv("del", cidr, interface),
            )
        )

    mtu = to_int(desired.mtu)
    if mtu is not None and runtime.mtu is not None and mtu != runtime.mtu:
        steps.append(
            Step(
                kind="exec",
                why=f"set MTU {runtime.mtu} -> {mtu}",
                argv=("ip", "link", "set", "dev", interface, "mtu", str(mtu)),
            )
        )
    if not runtime.up:
        steps.append(
            Step(
                kind="exec",
                why="bring the interface up",
                argv=("ip", "link", "set", "dev", interface, "up"),
            )
        )
    return steps


def _route_steps(
    runtime: InterfaceRuntime,
    previous: InterfaceConfig | None,
    desired: InterfaceConfig,
    interface: str,
) -> list[Step]:
    steps: list[Step] = []
    if desired.table_mode == "off":
        return steps
    old = previous.all_allowed_ips() if previous is not None else frozenset()
    new = desired.all_allowed_ips()
    present = set(runtime.routes)

    for cidr in sorted(c for c in (new - old) if not is_default_route(c)):
        if route_covered(cidr, runtime.routes):
            continue
        steps.append(
            Step(
                kind="exec",
                why=f"route {cidr} to the tunnel (same rule as wg-quick add_route)",
                argv=_route_argv("add", cidr, interface),
            )
        )
    for cidr in sorted(c for c in (old - new) if not is_default_route(c)):
        if cidr not in present:
            continue
        steps.append(
            Step(
                kind="exec",
                why=f"drop route {cidr} that the configuration no longer covers",
                argv=_route_argv("del", cidr, interface),
            )
        )
    return steps


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def plan_change(
    target: Target,
    desired: bytes,
    *,
    previous: bytes | None = None,
    runner: Runner | None = None,
) -> ChangePlan:
    runner = runner or LocalRunner()
    current = files.read_bytes(target.conf_path)
    if previous is None:
        previous = files.read_previous(target.state_dir, target.interface, target.conf_path)

    desired_cfg = parse_bytes(desired, path=target.conf_path)
    issues = validate(desired_cfg) + subnet_warnings(desired_cfg)
    if has_errors(issues):
        raise ValidationError(issues, target.conf_path)
    warning_messages = [f"{i.code}: {i.message}" for i in issues if i.level == "warning"]

    previous_cfg = parse_bytes(previous, path=target.conf_path) if previous else None
    runtime = read_interface(target.interface, runner)

    reasons: list[str] = []
    if not runtime.exists:
        mode = "start"
        file_changed: set[str] = set()
        kernel_changed: set[str] = set()
        peers = PeerChanges()
        reasons.append("interface is not present in this network namespace")
    else:
        file_changed = _file_level_changes(previous_cfg, desired_cfg)
        kernel_changed, peers = _kernel_level_changes(runtime, desired_cfg, previous_cfg)
        mode = decide_mode(file_changed, kernel_changed, previous_cfg, desired_cfg)
        if file_changed:
            reasons.append("file-level directives changed: " + ", ".join(sorted(file_changed)))
        if kernel_changed:
            reasons.append("live state differs from the file: " + ", ".join(sorted(kernel_changed)))
        if mode == "noop":
            reasons.append("live state already matches the file")

    steps: list[Step] = []
    if mode == "bounce":
        if current != previous:
            steps.append(
                Step(
                    kind="write_file",
                    why="bounce: restore the previously applied file first so the old "
                        "PreDown/PostDown hooks and SaveConfig semantics run",
                    path=target.conf_path,
                    content=previous,
                )
            )
        steps.append(
            Step(kind="exec", why="bring the tunnel down", argv=("wg-quick", "down", target.conf_path))
        )
        steps.append(
            Step(kind="write_file", why="write the new configuration", path=target.conf_path, content=desired)
        )
        steps.append(
            Step(
                kind="exec",
                why="bring the tunnel up with the new configuration",
                argv=("wg-quick", "up", target.conf_path),
                retry_on_failure=True,
            )
        )
    else:
        if current != desired:
            steps.append(
                Step(
                    kind="write_file",
                    why="write the new configuration",
                    path=target.conf_path,
                    content=desired,
                )
            )
        if mode == "start":
            steps.append(
                Step(
                    kind="exec",
                    why="interface is absent: wg-quick up",
                    argv=("wg-quick", "up", target.conf_path),
                    retry_on_failure=True,
                )
            )
        else:
            if kernel_changed:
                steps.append(sync_step(target.conf_path, target.interface))
            if mode in ("sync_addr", "sync_addr_route"):
                steps.extend(_address_steps(runtime, previous_cfg, desired_cfg, target.interface))
            if mode == "sync_addr_route":
                steps.extend(_route_steps(runtime, previous_cfg, desired_cfg, target.interface))

    destructive = bool(peers.removed) or "listen_port" in kernel_changed
    disruptive = mode in ("start", "bounce") or "private_key" in kernel_changed

    if peers.removed:
        warning_messages.append(
            "peers_removed: wg syncconf deletes peers that are not in the file ("
            + ", ".join(peers.removed)
            + "); the file is the source of truth"
        )
    if disruptive and mode == "bounce":
        warning_messages.append(
            "bounce: the interface is torn down and rebuilt inside the container; packet "
            "flow through the tunnel is interrupted for the duration"
        )
    if mode == "start":
        warning_messages.append("start: wg-quick up will create the interface (and possibly a default route)")
    if desired_cfg.save_config_enabled:
        warning_messages.append(
            "save_config: wg-quick down rewrites the configuration file from the live interface"
        )
    if "private_key" in kernel_changed:
        warning_messages.append(
            "private_key: the interface public key changes, so every peer needs its "
            "[Peer] PublicKey updated before handshakes can succeed again"
        )
    if any(is_default_route(cidr) for cidr in desired_cfg.all_allowed_ips()):
        warning_messages.append(
            "default_route: this configuration routes all traffic through the tunnel; with a "
            "shared network namespace the panel's own egress follows it"
        )

    return ChangePlan(
        interface=target.interface,
        conf_path=target.conf_path,
        state_dir=target.state_dir,
        mode=mode,  # type: ignore[arg-type]
        reasons=reasons,
        steps=steps,
        peer_changes=peers,
        changed_fields=sorted(file_changed | kernel_changed),
        destructive=destructive,
        disruptive=disruptive,
        warnings=warning_messages,
        expected_revision=sha256_hex(current),
        desired_sha256=sha256_hex(desired),
    )
