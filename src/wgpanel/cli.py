"""``wgpanel`` command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence

from . import files
from .apply import apply as apply_plan
from .differ import Target, plan_change
from .doctor import run_doctor, worst_status
from .errors import RiskGateError, ValidationError, WgPanelError
from .parse import parse_bytes
from .runner import LocalRunner
from .runtime import read_interface
from .validate import subnet_warnings, validate

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2
EXIT_ERROR = 3


def _float_env(name: str, fallback: float) -> float:
    """Read a float from the environment, falling back on anything unparsable."""
    try:
        return float(os.environ.get(name, fallback))
    except ValueError:
        return fallback


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wgpanel",
        description="Hot-reload a lscr.io/linuxserver/wireguard configuration without "
                    "restarting the container.",
    )
    parser.add_argument("--version", action="version", version="wgpanel 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(target: argparse.ArgumentParser) -> None:
        target.add_argument("-i", "--interface", default="wg0", help="wireguard interface (default: wg0)")
        target.add_argument("--conf", default=None, help="path to the .conf file")
        target.add_argument(
            "--state-dir",
            default=files.DEFAULT_STATE_DIR,
            help=f"panel state directory (default: {files.DEFAULT_STATE_DIR})",
        )
        target.add_argument("--json", action="store_true", help="machine readable output")

    plan = sub.add_parser("plan", help="show what apply would do, without touching anything")
    add_common(plan)
    plan.add_argument("--desired-file", default=None, help="plan for this file instead of --conf")

    apply_cmd = sub.add_parser("apply", help="write the file and push it to the running interface")
    add_common(apply_cmd)
    apply_cmd.add_argument("--desired-file", default=None, help="apply this file instead of --conf")
    apply_cmd.add_argument("--allow-disruptive", action="store_true",
                           help="allow interface teardown or a private key change")
    apply_cmd.add_argument("--allow-destructive", action="store_true",
                           help="allow removing live peers or changing the listen port")

    show = sub.add_parser("show", help="print the live interface state (redacted)")
    add_common(show)

    validate_cmd = sub.add_parser("validate", help="validate a configuration file")
    add_common(validate_cmd)

    doctor = sub.add_parser("doctor", help="check that the panel can actually manage the interface")
    add_common(doctor)
    doctor.add_argument("--config-dir", default=None)

    serve = sub.add_parser("serve", help="run the web panel")
    serve.add_argument("-i", "--interface", default="wg0")
    serve.add_argument("--conf", default=None)
    serve.add_argument("--state-dir", default=files.DEFAULT_STATE_DIR)
    serve.add_argument("--config-dir", default=files.DEFAULT_CONFIG_DIR)
    serve.add_argument("--host", default=os.environ.get("PANEL_HOST", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("PANEL_PORT", "47710")))
    serve.add_argument(
        "--traffic-interval",
        type=float,
        default=_float_env("PANEL_TRAFFIC_INTERVAL", 1.0),
        help="seconds between traffic counter samples; 0 disables sampling "
             "(default: $PANEL_TRAFFIC_INTERVAL, or 1)",
    )
    serve.add_argument(
        "--user",
        default=os.environ.get("PANEL_USER", "admin"),
        help="login account (default: $PANEL_USER, or admin); the password is only ever "
             "read from $PANEL_PASSWORD, never from argv where `ps` could see it",
    )

    return parser


def _target(args: argparse.Namespace) -> Target:
    conf = args.conf or files.default_conf_path(files.DEFAULT_CONFIG_DIR, args.interface)
    return Target(interface=args.interface, conf_path=conf, state_dir=args.state_dir)


def _emit(args: argparse.Namespace, payload: dict, *, text: str = "") -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif text:
        print(text)


def _cmd_plan(args: argparse.Namespace) -> int:
    target = _target(args)
    desired = files.read_bytes(args.desired_file) if args.desired_file else files.read_bytes(target.conf_path)
    if not desired:
        print(f"{target.conf_path}: no such file (nothing to plan)", file=sys.stderr)
        return EXIT_ERROR
    plan = plan_change(target, desired, runner=LocalRunner())
    lines = [f"interface : {plan.interface}", f"mode      : {plan.mode}"]
    if plan.reasons:
        lines.append("reasons   :")
        lines.extend(f"  - {reason}" for reason in plan.reasons)
    if plan.peer_changes:
        lines.append(
            f"peers     : +{len(plan.peer_changes.added)} "
            f"-{len(plan.peer_changes.removed)} ~{len(plan.peer_changes.changed)}"
        )
    if plan.warnings:
        lines.append("warnings  :")
        lines.extend(f"  ! {warning}" for warning in plan.warnings)
    lines.append(f"steps     : {len(plan.steps)}")
    for index, step in enumerate(plan.steps, start=1):
        described = step.describe()
        if described["kind"] == "exec":
            lines.append(f"  {index}. exec {' '.join(described['argv'])}")
        else:
            lines.append(
                f"  {index}. write {described['path']} "
                f"({described['size']} bytes, sha256 {described['sha256']})"
            )
    _emit(args, plan.to_dict(), text="\n".join(lines))
    return EXIT_OK


def _cmd_apply(args: argparse.Namespace) -> int:
    target = _target(args)
    desired = files.read_bytes(args.desired_file) if args.desired_file else None
    result = apply_plan(
        target,
        desired,
        allow_disruptive=args.allow_disruptive,
        allow_destructive=args.allow_destructive,
        runner=LocalRunner(),
    )
    lines = [
        f"interface : {result.interface}",
        f"mode      : {result.mode}",
        f"ok        : {result.ok}",
        f"steps     : {result.steps_run} ({result.exec_count} commands)",
        f"revision  : {result.file_revision[:16]}",
    ]
    if result.history_entry:
        lines.append(f"history   : {result.history_entry}")
    if result.rolled_back:
        lines.append("rolled back to the previous configuration")
    for diff in result.verify:
        lines.append(f"verify    : {'ok ' if diff.ok else 'BAD'} {diff.field} = {diff.actual}")
    for error in result.errors:
        lines.append(f"error     : {error}")
    for command in result.manual_commands:
        lines.append(f"manual    : {command}")
    _emit(args, result.to_dict(), text="\n".join(lines))
    return EXIT_OK if result.ok else EXIT_FAILED


def _cmd_show(args: argparse.Namespace) -> int:
    target = _target(args)
    runtime = read_interface(target.interface, runner=LocalRunner())
    payload = runtime.to_dict(redact=True)
    lines = [
        f"interface : {runtime.name}",
        f"exists    : {runtime.exists}",
        f"addresses : {', '.join(runtime.addresses) or '(none)'}",
        f"mtu       : {runtime.mtu}",
        f"up        : {runtime.up}",
        f"port      : {runtime.listen_port}",
        f"peers     : {len(runtime.peers)}",
    ]
    for peer in runtime.peers:
        lines.append(
            f"  {peer.key_id}: endpoint={peer.endpoint} allowed={','.join(peer.allowed_ips) or '-'} "
            f"handshake={peer.latest_handshake} rx={peer.rx} tx={peer.tx}"
        )
    _emit(args, payload, text="\n".join(lines))
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace) -> int:
    target = _target(args)
    raw = files.read_bytes(target.conf_path)
    if not raw:
        print(f"{target.conf_path}: no such file", file=sys.stderr)
        return EXIT_ERROR
    cfg = parse_bytes(raw, path=target.conf_path)
    issues = validate(cfg) + subnet_warnings(cfg)
    errors = [issue for issue in issues if issue.level == "error"]
    if args.json:
        print(json.dumps([issue.to_dict() for issue in issues], indent=2, ensure_ascii=False))
    else:
        for issue in issues:
            where = f" ({issue.where})" if issue.where else ""
            print(f"{issue.level:7} {issue.code}{where}: {issue.message}")
        if not issues:
            print(f"{target.conf_path}: ok")
    return EXIT_FAILED if errors else EXIT_OK


def _cmd_doctor(args: argparse.Namespace) -> int:
    target = _target(args)
    checks = run_doctor(target, runner=LocalRunner(), config_dir=args.config_dir or "")
    if args.json:
        print(json.dumps([check.to_dict() for check in checks], indent=2, ensure_ascii=False))
    else:
        for check in checks:
            print(f"{check.status:4} {check.id}: {check.message}")
            if check.hint and check.status != "ok":
                print(f"     hint: {check.hint}")
    return EXIT_FAILED if worst_status(checks) == "fail" else EXIT_OK


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .auth import AuthConfig
    from .web.app import create_app

    target = _target(args)
    auth = AuthConfig.from_environ(user=args.user)
    interval = args.traffic_interval if args.traffic_interval > 0 else None
    app = create_app(
        interface=target.interface,
        conf_path=target.conf_path,
        state_dir=target.state_dir,
        auth=auth,
        config_dir=args.config_dir,
        traffic_interval=interval,
    )
    sampling = f"traffic sampling every {interval:g}s" if interval else "traffic sampling off"
    reading = "read-only API token enabled" if auth.api_token else "read-only API token off"
    print(
        f"wgpanel listening on http://{args.host}:{args.port}  "
        f"(interface {target.interface}, user {auth.user}, {sampling}, {reading})"
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", access_log=False)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "plan": _cmd_plan,
        "apply": _cmd_apply,
        "show": _cmd_show,
        "validate": _cmd_validate,
        "doctor": _cmd_doctor,
        "serve": _cmd_serve,
    }
    try:
        return handlers[args.command](args)
    except (ValidationError, RiskGateError, WgPanelError) as exc:
        code = EXIT_REFUSED if isinstance(exc, (ValidationError, RiskGateError)) else EXIT_ERROR
        print(f"wgpanel: {exc}", file=sys.stderr)
        return code
    except KeyboardInterrupt:  # pragma: no cover
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
