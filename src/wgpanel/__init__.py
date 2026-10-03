"""wgpanel: hot-reload engine for lscr.io/linuxserver/wireguard.

The panel shares the wireguard container's network namespace, so every command
runs locally. Public surface:

    from wgpanel import Target, plan_change, apply, snapshot, run_doctor
"""

from .apply import apply, verify_against
from .differ import SYNC_SCRIPT, Target, plan_change
from .doctor import run_doctor, worst_status
from .errors import (
    CommandError,
    LockTimeout,
    RevisionMismatch,
    RiskGateError,
    RollbackError,
    ValidationError,
    WgPanelError,
)
from .files import atomic_write, default_conf_path, interface_lock
from .model import (
    ApplyResult,
    ChangePlan,
    Check,
    FieldDiff,
    InterfaceConfig,
    Issue,
    PeerChanges,
    PeerConfig,
    Step,
)
from .parse import load, parse_bytes, parse_text
from .runner import ExecResult, LocalRunner, Runner, redact_text
from .runtime import InterfaceRuntime, PeerRuntime, list_interfaces, read_interface, snapshot
from .validate import has_errors, validate

__version__ = "0.1.0"

__all__ = [
    "SYNC_SCRIPT",
    "ApplyResult",
    "ChangePlan",
    "Check",
    "CommandError",
    "ExecResult",
    "FieldDiff",
    "InterfaceConfig",
    "InterfaceRuntime",
    "Issue",
    "LocalRunner",
    "LockTimeout",
    "PeerChanges",
    "PeerConfig",
    "PeerRuntime",
    "RevisionMismatch",
    "RiskGateError",
    "RollbackError",
    "Runner",
    "Step",
    "Target",
    "ValidationError",
    "WgPanelError",
    "__version__",
    "apply",
    "atomic_write",
    "default_conf_path",
    "has_errors",
    "interface_lock",
    "list_interfaces",
    "load",
    "parse_bytes",
    "parse_text",
    "plan_change",
    "read_interface",
    "redact_text",
    "run_doctor",
    "snapshot",
    "validate",
    "verify_against",
    "worst_status",
]
