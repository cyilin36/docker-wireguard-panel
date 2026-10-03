"""Pre-flight checks: turn the plan's assumptions into something detectable."""

from __future__ import annotations

import json
import os

from . import files
from .differ import Target
from .model import Check
from .parse import parse_bytes
from .runner import LocalRunner, Runner
from .runtime import read_interface
from .validate import has_errors, subnet_warnings, validate


def _which(runner: Runner, binary: str) -> bool:
    result = runner.exec(["bash", "-c", f"command -v {binary}"], timeout=10.0)
    return result.ok and result.stdout.strip() != ""


def _default_route_dev(runner: Runner) -> str | None:
    result = runner.exec(["ip", "-j", "route", "show", "default"], timeout=10.0)
    if not result.ok or not result.stdout.strip():
        return None
    try:
        entries = json.loads(result.stdout)
    except ValueError:
        return None
    for entry in entries if isinstance(entries, list) else []:
        if entry.get("dev"):
            return str(entry["dev"])
    return None


def run_doctor(target: Target, *, runner: Runner | None = None, config_dir: str = "") -> list[Check]:
    runner = runner or LocalRunner()
    checks: list[Check] = []

    for binary, required in (("bash", True), ("wg", True), ("wg-quick", True), ("ip", True),
                             ("iptables", True), ("nft", False), ("tcpdump", False)):
        present = _which(runner, binary)
        if present:
            checks.append(Check(f"binary:{binary}", "ok", f"{binary} is available"))
        else:
            checks.append(
                Check(
                    f"binary:{binary}",
                    "fail" if required else "warn",
                    f"{binary} is not on PATH inside the panel",
                    "iptables is needed because the LinuxServer PostUp/PostDown hooks call it; "
                    "nft/tcpdump are only needed for the optional counters/capture features",
                )
            )

    result = runner.exec(["wg", "show", "interfaces"], timeout=10.0)
    if not result.ok:
        checks.append(
            Check(
                "netns:wg",
                "fail",
                "`wg show interfaces` failed: the panel is not in a namespace with the "
                "wireguard module, or it lacks NET_ADMIN",
                result.stderr.strip() or None,
            )
        )
    else:
        interfaces = [name for name in result.stdout.split() if name]
        checks.append(
            Check(
                "netns:wg",
                "ok",
                f"wireguard is reachable in this namespace (interfaces: {', '.join(interfaces) or 'none'})",
            )
        )
        if target.interface in interfaces:
            checks.append(Check("interface:present", "ok", f"{target.interface} exists"))
        else:
            checks.append(
                Check(
                    "interface:present",
                    "warn",
                    f"{target.interface} is not up right now",
                    "if the wireguard container is stopped, start it and retry",
                )
            )

    config_dir = config_dir or os.path.dirname(os.path.abspath(target.conf_path))
    if os.path.isdir(config_dir):
        writable = os.access(config_dir, os.W_OK)
        checks.append(
            Check(
                "config_dir",
                "ok" if writable else "fail",
                f"{config_dir} is {'writable' if writable else 'NOT writable'}",
                None if writable else "the panel must be able to rewrite the config atomically",
            )
        )
    else:
        checks.append(Check("config_dir", "fail", f"{config_dir} does not exist"))

    raw = files.read_bytes(target.conf_path)
    if not raw:
        checks.append(Check("config_file", "warn", f"{target.conf_path} does not exist yet"))
    else:
        cfg = parse_bytes(raw, path=target.conf_path)
        issues = validate(cfg) + subnet_warnings(cfg)
        errors = [i for i in issues if i.level == "error"]
        warnings = [i for i in issues if i.level == "warning"]
        if has_errors(issues):
            checks.append(
                Check(
                    "config_file",
                    "fail",
                    f"{target.conf_path} has {len(errors)} validation error(s)",
                    "; ".join(f"{i.code}: {i.message}" for i in errors),
                )
            )
        else:
            checks.append(
                Check(
                    "config_file",
                    "ok",
                    f"{target.conf_path} parses ({len(cfg.peers)} peers)"
                    + (f", {len(warnings)} warning(s)" if warnings else ""),
                    "; ".join(f"{i.code}: {i.message}" for i in warnings) or None,
                )
            )

    state = files.interface_state(target.state_dir, target.interface)
    if raw:
        current_revision = files.file_revision(target.conf_path)
        last = state.get("last_applied_sha256")
        if last and last != current_revision:
            checks.append(
                Check(
                    "drift:file",
                    "warn",
                    "the configuration file has changed since it was last applied",
                    "run `wgpanel plan` to see the difference, then `wgpanel apply`",
                )
            )
        elif last:
            checks.append(Check("drift:file", "ok", "the file matches the last applied revision"))

    runtime = read_interface(target.interface, runner)
    if runtime.exists and raw:
        cfg = parse_bytes(raw, path=target.conf_path)
        known = {peer.public_key for peer in cfg.peers}
        extra = [p.key_id for p in runtime.peers if p.public_key not in known]
        if extra:
            checks.append(
                Check(
                    "drift:peers",
                    "warn",
                    f"{len(extra)} live peer(s) are not in the file: {', '.join(extra)}",
                    "any apply removes peers that are absent from the file",
                )
            )
        elif cfg.peers:
            checks.append(Check("drift:peers", "ok", "every live peer is described by the file"))

    marker = os.path.join(os.path.dirname(os.path.abspath(config_dir.rstrip("/"))), ".donoteditthisfile")
    if os.path.exists(marker):
        checks.append(
            Check(
                "lsio:server_mode",
                "warn",
                "this container runs the LinuxServer 'server mode' (PEERS is set): "
                "the entrypoint regenerates wg0.conf whenever its environment variables change",
                "keep the file as the single source of truth and do not change PEERS/SERVERURL "
                "afterwards, or the panel's edits are overwritten on the next container start",
            )
        )
    else:
        checks.append(
            Check(
                "lsio:server_mode",
                "ok",
                "no .donoteditthisfile marker: the entrypoint will not regenerate wg0.conf",
            )
        )

    default_dev = _default_route_dev(runner)
    if default_dev == target.interface:
        checks.append(
            Check(
                "netns:default_route",
                "warn",
                f"the default route goes through {target.interface}: the panel's own egress "
                "uses the tunnel, so a bounce can cut the UI off",
                "keep disruptive applies away from client-mode tunnels you are connected through",
            )
        )
    else:
        checks.append(
            Check(
                "netns:default_route",
                "ok",
                f"the default route is unaffected (dev: {default_dev or 'unknown'})",
            )
        )

    return checks


def worst_status(checks: list[Check]) -> str:
    if any(check.status == "fail" for check in checks):
        return "fail"
    if any(check.status == "warn" for check in checks):
        return "warn"
    return "ok"
