"""Execute a plan: run the steps, verify the result, roll back on failure."""

from __future__ import annotations

import time

from . import files
from .differ import Target, plan_change
from .errors import CommandError, RevisionMismatch, RiskGateError, RollbackError, WgPanelError
from .model import (
    ApplyResult,
    FieldDiff,
    InterfaceConfig,
    Step,
    address_cidr,
    is_default_route,
    normalize_cidr,
    normalize_endpoint,
    sha256_hex,
    to_int,
)
from .parse import parse_bytes
from .runner import LocalRunner, Runner
from .runtime import InterfaceRuntime, read_interface, route_covered

EXEC_TIMEOUT = 60.0


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #
def verify_against(desired: InterfaceConfig, runtime: InterfaceRuntime) -> list[FieldDiff]:
    """Compare the live interface with what the file asks for."""
    diffs: list[FieldDiff] = []

    def add(field: str, expected: object, actual: object, ok: bool) -> None:
        diffs.append(FieldDiff(field, str(expected), str(actual), ok))

    if not runtime.exists:
        add("interface", "present", "absent", False)
        return diffs

    if desired.private_key:
        matches = desired.private_key == runtime.private_key
        add("private_key", "matches file", "matches file" if matches else "differs", matches)

    listen_port = to_int(desired.listen_port)
    if listen_port is not None:
        add("listen_port", listen_port, runtime.listen_port, listen_port == runtime.listen_port)

    want_addresses = {cidr for cidr in (address_cidr(a) for a in desired.address) if cidr}
    have_addresses = {cidr for cidr in (normalize_cidr(a) for a in runtime.addresses) if cidr}
    if want_addresses:
        missing = sorted(want_addresses - have_addresses)
        add(
            "addresses",
            ",".join(sorted(want_addresses)),
            ",".join(sorted(have_addresses)) or "(none)",
            not missing,
        )

    mtu = to_int(desired.mtu)
    if mtu is not None and runtime.mtu is not None:
        add("mtu", mtu, runtime.mtu, mtu == runtime.mtu)

    if desired.table_mode != "off":
        routable = [c for c in desired.all_allowed_ips() if not is_default_route(c)]
        if routable:
            missing_routes = [c for c in sorted(routable) if not route_covered(c, runtime.routes)]
            add(
                "routes",
                ",".join(sorted(routable)),
                "missing " + ",".join(missing_routes) if missing_routes else "all present",
                not missing_routes,
            )

    for peer in desired.peers:
        live = runtime.peer_by_key(peer.public_key)
        if live is None:
            add(f"peer:{peer.key_id}", "present", "absent", False)
            continue
        add(
            f"peer:{peer.key_id}:allowed_ips",
            ",".join(sorted(peer.allowed_ip_set())),
            ",".join(sorted(live.allowed_ip_set())) or "(none)",
            peer.allowed_ip_set() == live.allowed_ip_set(),
        )
        if peer.endpoint is not None:
            add(
                f"peer:{peer.key_id}:endpoint",
                normalize_endpoint(peer.endpoint),
                normalize_endpoint(live.endpoint),
                normalize_endpoint(peer.endpoint) == normalize_endpoint(live.endpoint),
            )
        keepalive = to_int(peer.persistent_keepalive)
        if keepalive is not None:
            add(
                f"peer:{peer.key_id}:keepalive",
                keepalive,
                live.persistent_keepalive,
                keepalive == live.persistent_keepalive,
            )

    extra = [p.key_id for p in runtime.peers if desired.peer_by_key(p.public_key) is None]
    if extra:
        add("peers_extra", "none", ",".join(extra), False)

    return diffs


# --------------------------------------------------------------------------- #
# step execution
# --------------------------------------------------------------------------- #
def _execute_step(step: Step, runner: Runner) -> int:
    """Run one step; returns 1 if it was a command (for reporting)."""
    if step.kind == "write_file":
        files.atomic_write(step.path or "", step.content or b"")
        return 0
    result = runner.exec(step.argv, timeout=EXEC_TIMEOUT)
    if not result.ok and step.retry_on_failure:
        result = runner.exec(step.argv, timeout=EXEC_TIMEOUT)
    if not result.ok:
        raise CommandError(step, result)
    return 1


def _run_steps(steps: list[Step], runner: Runner) -> tuple[int, int]:
    executed = 0
    commands = 0
    for step in steps:
        commands += _execute_step(step, runner)
        executed += 1
    return executed, commands


def _manual_commands(conf_path: str, history_entry: str | None) -> list[str]:
    commands = []
    if history_entry:
        commands.append(f"cp {history_entry} {conf_path}")
    commands.append(f"wg-quick up {conf_path}")
    return commands


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #
def apply(
    target: Target,
    desired: bytes | None = None,
    *,
    plan=None,
    allow_disruptive: bool = False,
    allow_destructive: bool = False,
    runner: Runner | None = None,
) -> ApplyResult:
    runner = runner or LocalRunner()
    started = time.monotonic()

    with files.interface_lock(target.state_dir, target.interface):
        current = files.read_bytes(target.conf_path)
        desired_bytes = current if desired is None else desired
        previous_bytes = files.read_previous(target.state_dir, target.interface, target.conf_path)

        if plan is None:
            plan = plan_change(target, desired_bytes, previous=previous_bytes, runner=runner)
        else:
            actual = sha256_hex(current)
            if plan.expected_revision and actual != plan.expected_revision:
                raise RevisionMismatch(target.conf_path, plan.expected_revision, actual)

        gate_reasons: list[str] = []
        gate_flags: list[str] = []
        if plan.disruptive and not allow_disruptive:
            gate_reasons.append("the change is disruptive (interface teardown or key change)")
            gate_flags.append("--allow-disruptive")
        if plan.destructive and not allow_destructive:
            gate_reasons.append("the change removes live state (peers or listen port)")
            gate_flags.append("--allow-destructive")
        if gate_reasons:
            raise RiskGateError(gate_reasons, gate_flags)

        history_entry = files.save_history(target.state_dir, target.interface, previous_bytes)

        result = ApplyResult(
            ok=True,
            interface=target.interface,
            mode=plan.mode,
            history_entry=history_entry,
            file_revision=sha256_hex(desired_bytes),
        )

        try:
            executed, commands = _run_steps(plan.steps, runner)
            result.steps_run = executed
            result.exec_count = commands
        except WgPanelError as exc:
            result.errors.append(str(exc))
            result.ok = False
            ok, critical, rollback_error = _rollback(target, previous_bytes, runner)
            result.rolled_back = ok
            result.critical = critical
            if rollback_error is not None:
                result.errors.append(str(rollback_error))
            result.manual_commands = _manual_commands(target.conf_path, history_entry)
            result.duration_ms = int((time.monotonic() - started) * 1000)
            files.update_interface_state(
                target.state_dir,
                target.interface,
                last_error=result.errors[0],
                last_mode=plan.mode,
            )
            return result

        final_runtime = read_interface(target.interface, runner)
        result.verify = verify_against(parse_bytes(desired_bytes, path=target.conf_path), final_runtime)
        if any(not diff.ok for diff in result.verify):
            result.ok = False
            result.errors.append("post-apply verification found differences")

        files.save_history(target.state_dir, target.interface, desired_bytes)
        files.save_applied(target.state_dir, target.interface, desired_bytes)
        files.update_interface_state(
            target.state_dir,
            target.interface,
            last_applied_sha256=sha256_hex(desired_bytes),
            last_applied_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            last_mode=plan.mode,
            last_ok=result.ok,
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result


def _rollback(
    target: Target,
    previous_bytes: bytes,
    runner: Runner,
) -> tuple[bool, bool, Exception | None]:
    """Restore the file and, best effort, the previous live state."""
    if previous_bytes:
        try:
            files.atomic_write(target.conf_path, previous_bytes)
        except OSError as exc:  # pragma: no cover - disk problems
            return False, True, exc

    try:
        recovery = plan_change(
            target,
            previous_bytes,
            previous=previous_bytes,
            runner=runner,
        )
        for step in recovery.steps:
            _execute_step(step, runner)
    except Exception as exc:
        return False, True, RollbackError(RuntimeError("apply failed"), exc)
    return True, False, None
