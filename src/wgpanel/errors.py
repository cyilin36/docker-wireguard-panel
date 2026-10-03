"""Exception types raised by the wgpanel reload engine."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .model import Issue, Step
    from .runner import ExecResult


class WgPanelError(Exception):
    """Base class for every error raised by this package."""


class ValidationError(WgPanelError):
    """The desired configuration is not something wg-quick could load."""

    def __init__(self, issues: Sequence[Issue], path: str = "") -> None:
        self.issues = list(issues)
        self.path = path
        errors = [i for i in self.issues if i.level == "error"]
        detail = "; ".join(f"{i.code}: {i.message}" for i in errors) or "invalid configuration"
        prefix = f"{path}: " if path else ""
        super().__init__(prefix + detail)


class RevisionMismatch(WgPanelError):
    """The file changed between planning and applying."""

    def __init__(self, path: str, expected: str, actual: str) -> None:
        self.path = path
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"{path} changed after the plan was made "
            f"(expected sha256 {expected[:16]}, found {actual[:16]}); re-run plan"
        )


class RiskGateError(WgPanelError):
    """An operation needs an explicit opt-in flag."""

    def __init__(self, reasons: Sequence[str], flags: Sequence[str]) -> None:
        self.reasons = list(reasons)
        self.flags = list(flags)
        super().__init__("refusing to continue: " + "; ".join(reasons)
                         + " (pass " + " ".join(self.flags) + " to allow)")


class CommandError(WgPanelError):
    """A command executed inside the target network namespace failed."""

    def __init__(self, step: Step, result: ExecResult) -> None:
        self.step = step
        self.result = result
        super().__init__(
            f"command failed with exit code {result.exit_code}: {' '.join(result.argv)}\n"
            f"{result.stderr.strip()}"
        )


class LockTimeout(WgPanelError):
    """Another wgpanel process holds the per-interface lock."""


class RollbackError(WgPanelError):
    """Applying the new configuration failed *and* the rollback failed."""

    def __init__(self, original: BaseException, rollback: BaseException) -> None:
        self.original = original
        self.rollback = rollback
        super().__init__(
            f"apply failed ({original}) and the rollback also failed ({rollback}); "
            "manual intervention required"
        )
