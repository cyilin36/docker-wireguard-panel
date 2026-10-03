"""Subprocess boundary.

Every command the engine runs goes through a :class:`Runner`. Tests substitute
:class:`wgpanel.testing.RecordingRunner`; production uses :class:`LocalRunner`,
which executes directly in the caller's network namespace (the panel shares the
wireguard container's netns).
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from typing import NamedTuple, Protocol


class ExecResult(NamedTuple):
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict:
        return {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class Runner(Protocol):
    def exec(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 30.0,
        stdin: bytes | None = None,
    ) -> ExecResult:
        ...


class LocalRunner:
    """Run commands in this container's namespaces."""

    def exec(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 30.0,
        stdin: bytes | None = None,
    ) -> ExecResult:
        cmd = [str(part) for part in argv]
        # Never let a child inherit our stdin: `wg pubkey` reads it, and an
        # inherited stream would hang the call. In text mode subprocess wants a
        # str on stdin, so decode here rather than in every caller.
        extra: dict = (
            {"input": stdin.decode("utf-8", errors="replace")}
            if stdin is not None
            else {"stdin": subprocess.DEVNULL}
        )
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
                **extra,
            )
        except FileNotFoundError as exc:
            return ExecResult(tuple(cmd), 127, "", f"{cmd[0]}: {exc.strerror or exc}")
        except subprocess.TimeoutExpired:
            return ExecResult(tuple(cmd), 124, "", f"timed out after {timeout}s")
        return ExecResult(tuple(cmd), proc.returncode, proc.stdout or "", proc.stderr or "")


def redact_text(text: str) -> str:
    """Strip private key material out of captured command output."""
    out = []
    for line in text.splitlines():
        lowered = line.strip().lower()
        if lowered.startswith(("privatekey", "presharedkey")):
            key, sep, _ = line.partition("=")
            out.append(f"{key}{sep} (redacted)" if sep else "(redacted)")
        else:
            out.append(line)
    return "\n".join(out)
