"""Filesystem side of the engine.

Two file trees are involved:

``conf_path``
    the live ``*.conf`` inside the wireguard container's ``/config`` bind mount.
``state_dir``
    panel state. **Deliberately outside the wg_confs directory** (default
    ``/config/.wgpanel``): the LinuxServer image globs ``/config/wg_confs/*.conf``
    and uses ``ls -A`` on that directory to decide whether to migrate an old
    layout, so nothing the panel owns may live there.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

from .errors import LockTimeout, WgPanelError

DEFAULT_CONFIG_DIR = "/config/wg_confs"
DEFAULT_STATE_DIR = "/config/.wgpanel"
DEFAULT_HISTORY_KEEP = 20


# --------------------------------------------------------------------------- #
# basic paths
# --------------------------------------------------------------------------- #
def default_conf_path(config_dir: str, interface: str) -> str:
    return os.path.join(config_dir, f"{interface}.conf")


def assert_within(base: str, path: str) -> str:
    """Resolve ``path`` and refuse anything that escapes ``base``."""
    base_real = os.path.realpath(base)
    target_real = os.path.realpath(path)
    if target_real != base_real and not target_real.startswith(base_real + os.sep):
        raise WgPanelError(f"{path!r} resolves outside {base!r}")
    return target_real


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def read_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return b""


def append_bytes(path: str, data: bytes) -> None:
    """Append ``data`` to ``path``, creating it if needed.

    Binary on purpose: the traffic journal must round-trip byte for byte, and a
    text-mode write would be free to translate newlines. ``fsync`` costs one disk
    flush per append, which is once a minute here — cheap next to the guarantee
    that a killed panel does not lose the last samples.
    """
    ensure_dir(os.path.dirname(os.path.abspath(path)) or ".")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def file_revision(path: str) -> str:
    return hashlib.sha256(read_bytes(path)).hexdigest()


# --------------------------------------------------------------------------- #
# atomic writes
# --------------------------------------------------------------------------- #
def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(
    path: str,
    data: bytes,
    *,
    mode: int | None = None,
    owner: tuple[int, int] | None = None,
) -> None:
    """Write ``data`` to ``path`` atomically, preserving mode and ownership.

    ``os.replace`` swaps the inode, so the new file would otherwise be owned by
    the panel's uid/gid and lose the permissions the LinuxServer image set.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(directory)

    existing = None
    with contextlib.suppress(FileNotFoundError):
        existing = os.stat(path)

    tmp = os.path.join(directory, f".{os.path.basename(path)}.tmp-{uuid.uuid4().hex}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)

    target_mode = mode if mode is not None else (existing.st_mode & 0o777 if existing else 0o600)
    os.chmod(tmp, target_mode)
    if owner is None and existing is not None:
        owner = (existing.st_uid, existing.st_gid)
    if owner is not None:
        with contextlib.suppress(OSError):
            os.chown(tmp, owner[0], owner[1])

    try:
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    _fsync_dir(directory)


# --------------------------------------------------------------------------- #
# history / applied copies / state
# --------------------------------------------------------------------------- #
def applied_path(state_dir: str, interface: str) -> str:
    return os.path.join(state_dir, "applied", f"{interface}.conf")


def history_dir(state_dir: str, interface: str) -> str:
    return os.path.join(state_dir, "history", interface)


def read_applied(state_dir: str, interface: str) -> bytes:
    return read_bytes(applied_path(state_dir, interface))


def read_previous(state_dir: str, interface: str, conf_path: str) -> bytes:
    """Last content known to be live; falls back to the file on first run."""
    applied = read_applied(state_dir, interface)
    if applied:
        return applied
    return read_bytes(conf_path)


def save_applied(state_dir: str, interface: str, data: bytes) -> str:
    path = applied_path(state_dir, interface)
    atomic_write(path, data, mode=0o600)
    return path


def save_history(
    state_dir: str,
    interface: str,
    data: bytes,
    *,
    keep: int = DEFAULT_HISTORY_KEEP,
) -> str | None:
    if not data:
        return None
    directory = ensure_dir(history_dir(state_dir, interface))
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(data).hexdigest()[:8]
    path = os.path.join(directory, f"{interface}-{stamp}-{digest}.conf")
    atomic_write(path, data, mode=0o600)
    prune_history(state_dir, interface, keep)
    return path


def prune_history(state_dir: str, interface: str, keep: int) -> list[str]:
    directory = history_dir(state_dir, interface)
    try:
        entries = sorted(
            (os.path.join(directory, name) for name in os.listdir(directory)),
            key=lambda p: os.path.getmtime(p),
            reverse=True,
        )
    except FileNotFoundError:
        return []
    removed = []
    for path in entries[keep:]:
        with contextlib.suppress(OSError):
            os.unlink(path)
            removed.append(path)
    return removed


def state_path(state_dir: str) -> str:
    return os.path.join(state_dir, "state.json")


def load_state(state_dir: str) -> dict:
    raw = read_bytes(state_path(state_dir))
    if not raw:
        return {"version": 1, "interfaces": {}}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"version": 1, "interfaces": {}}
    data.setdefault("version", 1)
    data.setdefault("interfaces", {})
    return data


def interface_state(state_dir: str, interface: str) -> dict:
    return load_state(state_dir).get("interfaces", {}).get(interface, {})


def update_interface_state(state_dir: str, interface: str, **fields: object) -> dict:
    data = load_state(state_dir)
    entry = data.setdefault("interfaces", {}).setdefault(interface, {})
    entry.update(fields)
    ensure_dir(state_dir)
    atomic_write(
        state_path(state_dir),
        json.dumps(data, indent=2, sort_keys=True).encode("utf-8"),
        mode=0o600,
    )
    return entry


# --------------------------------------------------------------------------- #
# locking
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def interface_lock(
    state_dir: str,
    interface: str,
    *,
    timeout: float = 10.0,
    poll: float = 0.1,
) -> Iterator[None]:
    lock_dir = ensure_dir(os.path.join(state_dir, "locks"))
    path = os.path.join(lock_dir, f"{interface}.lock")
    with open(path, "a+") as handle:
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LockTimeout(
                            f"another wgpanel process holds the lock on {interface} "
                            f"({path}); giving up after {timeout}s"
                        ) from None
                    time.sleep(poll)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
