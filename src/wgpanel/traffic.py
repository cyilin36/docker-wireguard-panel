"""Sampled traffic history for the wireguard interface.

The kernel only ever hands out a *cumulative* byte counter per peer, and a
waveform needs the deltas between consecutive readings. So the panel samples
those counters and keeps the result at three granularities:

``second``
    the last few minutes, memory only. This is what the "1 分钟" range plots.
``minute``
    26 hours of per-minute deltas, appended to ``minute.jsonl``.
``hour``
    15 days of per-hour deltas, appended to ``hour.jsonl``.

Both journals are append-only and pruned by an occasional atomic rewrite, so the
panel never rewrites a growing file every few seconds. Lifetime totals live in
``totals.json`` and are monotonic: a counter reset (interface or container
restart) costs at most the bytes moved since the previous sample.

Everything is keyed by public key, never by peer name — renaming a peer must not
split its history.

Direction follows the panel's convention, fixed here once: ``up`` is what the
server *received* (client → server, wg's ``rx``) and ``down`` is what the server
*sent* (server → client, wg's ``tx``).
"""

from __future__ import annotations

import json
import os
import time
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any

from . import files
from .errors import WgPanelError
from .runner import Runner
from .runtime import WG_LIST_TIMEOUT, parse_dump

BUCKETS = 60
SECOND_BUFFER = 180
MINUTE_KEEP = 26 * 3600
HOUR_KEEP = 15 * 86400 + 3600
MINUTE_PRUNE_EVERY = 6 * 3600
HOUR_PRUNE_EVERY = 24 * 3600

SECOND_WINDOW = 60
WINDOWS: dict[int, str] = {
    60: "1分钟",
    3600: "1小时",
    43200: "12小时",
    86400: "24小时",
    604800: "7天",
    1296000: "15天",
}

MINUTE_NAME = "minute.jsonl"
HOUR_NAME = "hour.jsonl"
TOTALS_NAME = "totals.json"


def read_counters(runner: Runner, interface: str) -> dict[str, tuple[int, int]] | None:
    """One ``wg show <iface> dump`` worth of ``public_key -> (rx, tx)``.

    ``None`` means the interface could not be read (container restarting, device
    gone); callers must not treat that as "everything dropped to zero".
    """
    result = runner.exec(["wg", "show", interface, "dump"], timeout=WG_LIST_TIMEOUT)
    if not result.ok or not result.stdout.strip():
        return None
    counters: dict[str, tuple[int, int]] = {}
    for peer in parse_dump(result.stdout).peers:
        if peer.public_key:
            counters[peer.public_key] = (peer.rx, peer.tx)
    return counters


@dataclass
class Bucket:
    """Bytes moved in one time slice, ``up`` first to match the JSON layout.

    ``width`` is how many seconds the slice covers. It is not persisted: it is
    implied by the tier a row was read from, and the rate has to divide by the
    coverage actually present in a slice — a 10080-second bucket rarely holds a
    whole number of 3600-second rows, and dividing by the nominal width would
    turn a flat stream into a 1.4/2.1 sawtooth.
    """

    ts: int
    up: int = 0
    down: int = 0
    peers: dict[str, list[int]] = field(default_factory=dict)
    width: int = 60

    def add(self, deltas: dict[str, tuple[int, int]]) -> None:
        for key, (up, down) in deltas.items():
            self.up += up
            self.down += down
            slot = self.peers.setdefault(key, [0, 0])
            slot[0] += up
            slot[1] += down

    def merge(self, other: Bucket) -> None:
        self.up += other.up
        self.down += other.down
        for key, value in other.peers.items():
            slot = self.peers.setdefault(key, [0, 0])
            slot[0] += value[0]
            slot[1] += value[1]

    def to_json(self) -> dict:
        return {"t": self.ts, "u": self.up, "d": self.down, "p": self.peers}


def _int_pair(value: Any) -> bool:
    return isinstance(value, list) and len(value) == 2 and all(isinstance(item, int) for item in value)


def bucket_from_json(raw: Any) -> Bucket | None:
    """Rebuild a bucket, returning ``None`` for anything malformed.

    A journal is appended to while the panel is running, so the last line can be
    truncated by a hard kill; unreadable lines are skipped rather than fatal.
    """
    if not isinstance(raw, dict):
        return None
    ts, up, down = raw.get("t"), raw.get("u"), raw.get("d")
    if not isinstance(ts, int) or not isinstance(up, int) or not isinstance(down, int):
        return None
    peers: dict[str, list[int]] = {}
    raw_peers = raw.get("p")
    if isinstance(raw_peers, dict):
        for key, value in raw_peers.items():
            if isinstance(key, str) and _int_pair(value):
                peers[key] = [value[0], value[1]]
    return Bucket(ts=ts, up=up, down=down, peers=peers)


class TrafficStore:
    """Sample counters, aggregate them, and serve 60-point series."""

    def __init__(
        self,
        state_dir: str,
        *,
        interface: str = "wg0",
        runner: Runner,
        clock=time.time,
    ) -> None:
        self.state_dir = state_dir
        self.interface = interface
        self.runner = runner
        self._clock = clock
        self.directory = os.path.join(state_dir, "traffic")
        self.error: str | None = None

        self._since = 0
        self._totals_all = [0, 0]  # [up, down]
        self._totals: dict[str, list[int]] = {}
        self._baseline: dict[str, tuple[int, int]] = {}
        self._seconds: deque[tuple[int, dict[str, tuple[int, int]], tuple[int, int]]] = deque(
            maxlen=SECOND_BUFFER
        )
        self._minute: Bucket | None = None
        self._hour_ts = 0
        self._hour_rows: list[Bucket] = []
        self._last_ts = 0
        self._next_prune = 0.0
        self._minute_cache: tuple[int, int, list[Bucket]] | None = None
        self._hour_cache: tuple[int, int, list[Bucket]] | None = None

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #
    def _path(self, name: str) -> str:
        return os.path.join(self.directory, name)

    def load(self) -> None:
        """Read the journals and totals; safe to call on a missing state dir."""
        self._load_totals()
        now = int(self._clock())
        minute_ts = now - now % 60
        hour_ts = now - now % 3600
        minutes = self._read_rows(MINUTE_NAME)
        # A previous run may have stopped mid-minute or mid-hour; pick the
        # partial slices back up instead of dropping them.
        self._minute = next((row for row in minutes if row.ts == minute_ts), None)
        self._hour_rows = [row for row in minutes if hour_ts <= row.ts < hour_ts + 3600]
        self._hour_ts = hour_ts
        self._last_ts = 0
        self._prune(now, force=True)

    def _load_totals(self) -> None:
        raw = files.read_bytes(self._path(TOTALS_NAME))
        if not raw:
            return
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(data, dict):
            return
        since = data.get("since")
        if isinstance(since, int) and since > 0:
            self._since = since
        if _int_pair(data.get("a")):
            self._totals_all = list(data["a"])
        peers = data.get("p")
        if isinstance(peers, dict):
            for key, value in peers.items():
                if isinstance(key, str) and _int_pair(value):
                    self._totals[key] = [value[0], value[1]]

    def _save_totals(self) -> None:
        payload = {"since": self._since, "a": self._totals_all, "p": self._totals}
        try:
            files.atomic_write(
                self._path(TOTALS_NAME),
                json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                mode=0o600,
            )
        except OSError as exc:
            self.error = str(exc)

    def _append_row(self, name: str, bucket: Bucket) -> None:
        line = json.dumps(bucket.to_json(), separators=(",", ":")) + "\n"
        try:
            files.append_bytes(self._path(name), line.encode("utf-8"))
        except OSError as exc:
            self.error = str(exc)

    def _read_rows(self, name: str) -> list[Bucket]:
        path = self._path(name)
        try:
            stat = os.stat(path)
        except OSError:
            return []
        key = (stat.st_mtime_ns, stat.st_size)
        cache = self._minute_cache if name == MINUTE_NAME else self._hour_cache
        if cache is not None and (cache[0], cache[1]) == key:
            return cache[2]
        rows: dict[int, Bucket] = {}
        for line in files.read_bytes(path).splitlines():
            if not line.strip():
                continue
            try:
                raw = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            bucket = bucket_from_json(raw)
            if bucket is not None:
                rows[bucket.ts] = bucket
        ordered = [rows[ts] for ts in sorted(rows)]
        if name == MINUTE_NAME:
            self._minute_cache = (key[0], key[1], ordered)
        else:
            self._hour_cache = (key[0], key[1], ordered)
        return ordered

    def _prune(self, now: int, *, force: bool = False) -> None:
        if not force and now < self._next_prune:
            return
        self._next_prune = now + MINUTE_PRUNE_EVERY
        self._rewrite(MINUTE_NAME, now - MINUTE_KEEP)
        self._rewrite(HOUR_NAME, now - HOUR_KEEP)

    def _rewrite(self, name: str, cutoff: int) -> None:
        rows = self._read_rows(name)
        kept = [row for row in rows if row.ts >= cutoff]
        if len(kept) == len(rows):
            return
        blob = "".join(json.dumps(row.to_json(), separators=(",", ":")) + "\n" for row in kept)
        try:
            files.atomic_write(self._path(name), blob.encode("utf-8"), mode=0o600)
        except OSError as exc:
            self.error = str(exc)
            return
        if name == MINUTE_NAME:
            self._minute_cache = None
        else:
            self._hour_cache = None

    # ------------------------------------------------------------------ #
    # sampling
    # ------------------------------------------------------------------ #
    def sample_once(self) -> bool:
        """Read the counters once; returns False when the interface is unreadable."""
        counters = read_counters(self.runner, self.interface)
        if counters is None:
            return False

        now = int(self._clock())
        if self._last_ts and now < self._last_ts:
            # The wall clock stepped backwards. Re-baseline rather than inventing
            # a negative interval.
            self._baseline = {}
            self._last_ts = 0
            self._seconds.clear()

        deltas: dict[str, tuple[int, int]] = {}
        for key, (up, down) in counters.items():
            previous = self._baseline.get(key)
            if previous is None:
                delta_up = delta_down = 0
            else:
                # A counter that moved backwards means the interface (or the
                # container) restarted. Those bytes are unknowable; keep the
                # lifetime total monotonic and start a fresh baseline.
                delta_up = up - previous[0] if up >= previous[0] else 0
                delta_down = down - previous[1] if down >= previous[1] else 0
            self._baseline[key] = (up, down)
            deltas[key] = (delta_up, delta_down)

        if not self._since:
            # First run: adopt the counters already on the interface so the
            # lifetime total does not start at zero while the peer table shows
            # gigabytes.
            self._since = now
            for key, (up, down) in counters.items():
                self._totals.setdefault(key, [up, down])
            self._totals_all = [
                sum(value[0] for value in self._totals.values()),
                sum(value[1] for value in self._totals.values()),
            ]

        self._record(now, deltas)
        # Retention has to be enforced while running too, not only at load: a
        # panel that stays up for months would otherwise never trim the journals.
        self._prune(now)
        self._last_ts = now
        return True

    def _record(self, now: int, deltas: dict[str, tuple[int, int]]) -> None:
        for key, (up, down) in deltas.items():
            slot = self._totals.setdefault(key, [0, 0])
            slot[0] += up
            slot[1] += down
            self._totals_all[0] += up
            self._totals_all[1] += down
        all_up = sum(value[0] for value in deltas.values())
        all_down = sum(value[1] for value in deltas.values())
        self._seconds.append((now, deltas, (all_up, all_down)))

        minute_ts = now - now % 60
        hour_ts = now - now % 3600
        if self._minute is None:
            self._minute = Bucket(ts=minute_ts)
        elif self._minute.ts != minute_ts:
            self._close_minute()
            self._minute = Bucket(ts=minute_ts)
        self._minute.add(deltas)
        # The minute rollover has to run first: the last minute of an hour only
        # becomes part of that hour when it is closed.
        if hour_ts != self._hour_ts:
            self._close_hour()
            self._hour_ts = hour_ts

    def _close_minute(self) -> None:
        bucket, self._minute = self._minute, None
        if bucket is None:
            return
        self._append_row(MINUTE_NAME, bucket)
        self._hour_rows.append(bucket)
        self._minute_cache = None

    def _close_hour(self) -> None:
        low, high = self._hour_ts, self._hour_ts + 3600
        rows, self._hour_rows = [row for row in self._hour_rows if low <= row.ts < high], []
        if not rows:
            return
        total = Bucket(ts=low)
        for row in rows:
            total.merge(row)
        self._append_row(HOUR_NAME, total)
        self._hour_cache = None

    def flush(self) -> None:
        """Persist the in-flight slices and the totals; meant for shutdown.

        It consumes the current minute/hour accumulators, so this is a
        shutdown-only operation — the sampler must not keep running afterwards.
        """
        if self._minute is not None:
            self._close_minute()
        if self._hour_ts:
            self._close_hour()
        if self._since:
            self._save_totals()

    # ------------------------------------------------------------------ #
    # read side
    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict:
        """Cheap (no file I/O) totals block for the 2s ``/api/state`` poll."""
        span = 1
        up_rate = down_rate = 0.0
        if self._seconds:
            last = self._seconds[-1]
            if len(self._seconds) >= 2:
                span = max(1, last[0] - self._seconds[-2][0])
            up_rate = last[2][0] / span
            down_rate = last[2][1] / span
        return {
            "since": self._since,
            "down": self._totals_all[1],
            "up": self._totals_all[0],
            "down_rate": round(down_rate, 1),
            "up_rate": round(up_rate, 1),
            "error": self.error,
        }

    def series(self, *, scope: str = "all", window: int = 3600, now: int | None = None) -> dict:
        if window not in WINDOWS:
            raise WgPanelError(
                f"unknown traffic window {window!r}; expected one of {sorted(WINDOWS)}"
            )
        now = int(self._clock()) if now is None else int(now)
        step = window // BUCKETS
        rows, tier = self._rows_for(window, now)
        return {
            "window": window,
            "scope": scope,
            "step": step,
            "tier": tier,
            "now": now,
            "points": _bucket_rates(rows, scope, now - window, step),
        }

    def _rows_for(self, window: int, now: int) -> tuple[list[Bucket], str]:
        if window <= SECOND_WINDOW:
            rows: list[Bucket] = []
            seconds = list(self._seconds)
            for index, (ts, deltas, (all_up, all_down)) in enumerate(seconds):
                # A sample's deltas cover the time until the next sample; the
                # last one reaches "now".
                following = seconds[index + 1][0] if index + 1 < len(seconds) else now
                rows.append(
                    Bucket(
                        ts=ts,
                        up=all_up,
                        down=all_down,
                        peers={key: list(value) for key, value in deltas.items()},
                        width=max(1, following - ts),
                    )
                )
            return rows, "second"
        if window <= MINUTE_KEEP:
            rows = list(self._read_rows(MINUTE_NAME))
            if self._minute is not None:
                rows.append(replace(self._minute, width=max(1, now - self._minute.ts)))
            return rows, "minute"
        # The hour tier is only appended when an hour closes, so blend in the
        # current hour's finished minutes plus the minute in progress.
        rows = [
            *(replace(row, width=3600) for row in self._read_rows(HOUR_NAME)),
            *self._hour_rows,
        ]
        if self._minute is not None:
            rows.append(replace(self._minute, width=max(1, now - self._minute.ts)))
        return rows, "hour"


def _bucket_rates(rows: list[Bucket], scope: str, start: int, step: int) -> list[list]:
    """Fold rows into exactly ``BUCKETS`` slices and convert bytes to bytes/s.

    A slice with no row at all stays ``None`` (the panel was not sampling, so the
    chart must break the line); a slice whose rows are all zero is a real ``0``
    (sampled, idle). The divisor is the coverage the slice actually holds, not
    the nominal width.
    """
    slots: list[list[int | None]] = [[None, None, 0] for _ in range(BUCKETS)]
    for row in rows:
        index = (row.ts - start) // step
        if index < 0 or index >= BUCKETS:
            continue
        if scope == "all":
            up, down = row.up, row.down
        else:
            value = row.peers.get(scope)
            if value is None:
                continue
            up, down = value[0], value[1]
        slot = slots[index]
        slot[0] = (slot[0] or 0) + up
        slot[1] = (slot[1] or 0) + down
        slot[2] = (slot[2] or 0) + max(0, row.width)

    points: list[list] = []
    for index, slot in enumerate(slots):
        ts = start + index * step
        if slot[0] is None and slot[1] is None:
            points.append([ts, None, None])
            continue
        covered = slot[2] or step
        points.append([ts, round((slot[1] or 0) / covered, 1), round((slot[0] or 0) / covered, 1)])
    return points
