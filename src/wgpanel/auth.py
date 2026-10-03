"""Login protection for the web panel.

Deliberately free of any web framework import: the middleware that uses this
lives in :mod:`wgpanel.web.app`, so the rules can be tested on their own.

The credentials come from two environment variables, which the compose file
sets on the panel container::

    PANEL_USER      account name (default: admin)
    PANEL_PASSWORD  password

Sessions are held in memory. A restart therefore logs everybody out, which is
also what makes a password change take effect: the panel is reconfigured
through its environment, so changing the password recreates the container.
"""

from __future__ import annotations

import hmac
import math
import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from .errors import WgPanelError

COOKIE_NAME = "wgpanel_session"
DEFAULT_SESSION_TTL = 7 * 24 * 3600

# Ten wrong passwords from one address lock that address for five minutes. Both
# numbers are deliberately not configurable: there is no reason to tune them,
# and one fewer knob is one fewer way to end up wide open.
MAX_ATTEMPTS = 10
LOCKOUT_SECONDS = 300.0

# Reachable without a session: the login page and the assets it needs.
PUBLIC_PATHS = frozenset({"/login", "/api/login", "/api/logout", "/api/health", "/favicon.ico"})
PUBLIC_PREFIXES = ("/static/",)


@dataclass(frozen=True)
class AuthConfig:
    """Who may log in."""

    user: str = "admin"
    password: str = ""
    session_ttl: int = DEFAULT_SESSION_TTL

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        user: str | None = None,
    ) -> AuthConfig:
        """Build the config, refusing to run an unprotected panel."""
        environ = os.environ if environ is None else environ
        name = (user or environ.get("PANEL_USER") or "admin").strip()
        secret = environ.get("PANEL_PASSWORD") or ""
        if not name:
            raise WgPanelError("PANEL_USER is empty")
        if not secret:
            raise WgPanelError(
                "PANEL_PASSWORD is not set, refusing to serve an unprotected panel; add "
                "`- PANEL_PASSWORD=...` to the wgpanel service in docker-compose.yml"
            )
        return cls(user=name, password=secret)

    def verify(self, user: str, password: str) -> bool:
        """Constant-time check of both fields.

        Both comparisons always run: an early return would make a wrong account
        name answer faster than a wrong password.
        """
        user_ok = hmac.compare_digest(user.encode("utf-8"), self.user.encode("utf-8"))
        password_ok = hmac.compare_digest(password.encode("utf-8"), self.password.encode("utf-8"))
        return user_ok and password_ok


class SessionStore:
    """In-memory tokens. No disk, so the panel can keep ``read_only: true``."""

    def __init__(self, ttl: int = DEFAULT_SESSION_TTL, *, clock: Callable[[], float] = time.time) -> None:
        self._ttl = float(ttl)
        self._clock = clock
        self._sessions: dict[str, tuple[str, float]] = {}

    def create(self, user: str) -> str:
        """Issue a brand new token, so a fixed session id can never be reused."""
        token = secrets.token_urlsafe(32)
        self._sessions[token] = (user, self._clock() + self._ttl)
        self.prune()
        return token

    def get(self, token: str | None) -> str | None:
        """Return the user, refreshing the expiry (sliding window)."""
        if not token:
            return None
        entry = self._sessions.get(token)
        if entry is None:
            return None
        user, expires = entry
        if expires <= self._clock():
            del self._sessions[token]
            return None
        self._sessions[token] = (user, self._clock() + self._ttl)
        return user

    def drop(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)

    def prune(self) -> None:
        now = self._clock()
        for token in [name for name, (_, expires) in self._sessions.items() if expires <= now]:
            del self._sessions[token]

    def __len__(self) -> int:
        return len(self._sessions)


class RateLimiter:
    """Sliding window of failed logins, keyed by client address."""

    def __init__(
        self,
        *,
        max_attempts: int = MAX_ATTEMPTS,
        window: float = LOCKOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_attempts
        self._window = window
        self._clock = clock
        self._failures: dict[str, list[float]] = {}

    def _recent(self, key: str) -> list[float]:
        now = self._clock()
        kept = [stamp for stamp in self._failures.get(key, []) if now - stamp < self._window]
        if kept:
            self._failures[key] = kept
        else:
            self._failures.pop(key, None)
        return kept

    def retry_after(self, key: str) -> int:
        """Seconds until this address may try again; 0 while it still may."""
        stamps = self._recent(key)
        if len(stamps) < self._max:
            return 0
        # The lock lifts once the oldest failure leaves the window.
        remaining = self._window - (self._clock() - stamps[0])
        return max(1, math.ceil(remaining))

    def record_failure(self, key: str) -> None:
        self._failures.setdefault(key, []).append(self._clock())
        self._recent(key)

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


@dataclass
class AuthGuard:
    """Everything the HTTP layer needs to know about the current request."""

    config: AuthConfig = field(default_factory=AuthConfig)
    sessions: SessionStore = field(default_factory=SessionStore)
    limiter: RateLimiter = field(default_factory=RateLimiter)

    @classmethod
    def for_config(cls, config: AuthConfig) -> AuthGuard:
        return cls(config=config, sessions=SessionStore(config.session_ttl), limiter=RateLimiter())

    def is_public(self, path: str) -> bool:
        return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)

    def user_for(self, token: str | None) -> str | None:
        return self.sessions.get(token)

    def attempt(self, user: str, password: str, client: str) -> str | None:
        """Return a fresh session token, or ``None`` when the login is refused."""
        if self.config.verify(user, password):
            self.limiter.reset(client)
            return self.sessions.create(self.config.user)
        self.limiter.record_failure(client)
        return None

    def retry_after(self, client: str) -> int:
        return self.limiter.retry_after(client)
