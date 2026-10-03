"""HTTP API and web UI."""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from urllib.parse import parse_qs, quote

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from .. import files
from ..apply import apply
from ..auth import COOKIE_NAME, AuthConfig, AuthGuard
from ..differ import Target, plan_change
from ..errors import RiskGateError, ValidationError, WgPanelError
from ..peers import UNSET, KeySource, PeerManager
from ..runner import LocalRunner, Runner
from ..runtime import read_interface

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class AuthMiddleware:
    """Deny-by-default gate in front of the router.

    Written as plain ASGI rather than ``BaseHTTPMiddleware``: it never touches
    the request body, so there is no need to pay for the buffering wrapper.
    """

    def __init__(self, app: ASGIApp, guard: AuthGuard) -> None:
        self.app = app
        self.guard = guard

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not self.guard.is_public(path):
            request = Request(scope)
            if self.guard.user_for(request.cookies.get(COOKIE_NAME)) is None:
                await self._refuse(scope, receive, send, path)
                return
        await self.app(scope, receive, send)

    async def _refuse(self, scope: Scope, receive: Receive, send: Send, path: str) -> None:
        if path.startswith("/api/"):
            response: Response = JSONResponse({"error": "未登录，请先登录"}, status_code=401)
        else:
            query = scope.get("query_string", b"").decode("latin-1")
            wanted = f"{path}?{query}" if query else path
            response = RedirectResponse(f"/login?next={quote(wanted, safe='')}", status_code=302)
        await response(scope, receive, send)


def create_app(
    *,
    interface: str,
    conf_path: str,
    state_dir: str,
    auth: AuthConfig,
    config_dir: str = "",
    runner: Runner | None = None,
    keys: KeySource | None = None,
) -> Starlette:
    runner = runner or LocalRunner()
    guard = AuthGuard.for_config(auth)
    target = Target(interface=interface, conf_path=conf_path, state_dir=state_dir)
    manager = PeerManager(
        target,
        runner=runner,
        keys=keys,
        config_dir=config_dir or os.path.dirname(os.path.abspath(conf_path)),
    )

    def api(handler: Callable[[object], Awaitable[Response]]) -> Callable[[object], Awaitable[Response]]:
        async def wrapper(request):
            try:
                return await handler(request)
            except ValidationError as exc:
                return JSONResponse(
                    {"error": str(exc), "issues": [issue.to_dict() for issue in exc.issues]},
                    status_code=422,
                )
            except RiskGateError as exc:
                return JSONResponse(
                    {"error": str(exc), "needs": exc.flags, "reasons": exc.reasons},
                    status_code=409,
                )
            except WgPanelError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)

        return wrapper

    async def read_json(request) -> dict:
        raw = await request.body()
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise WgPanelError(f"invalid JSON body: {exc}") from None
        return payload if isinstance(payload, dict) else {}

    async def read_login(request) -> dict:
        """Accept a JSON body or a plain form, without python-multipart.

        Starlette's ``request.form()`` needs python-multipart even for
        ``application/x-www-form-urlencoded``, which is too much baggage for
        two fields.
        """
        raw = await request.body()
        if not raw:
            return {}
        text = raw.decode("utf-8", "replace")
        if "json" in request.headers.get("content-type", ""):
            try:
                payload = json.loads(text)
            except ValueError:
                return {}
            return payload if isinstance(payload, dict) else {}
        fields = parse_qs(text, keep_blank_values=True)
        return {key: values[0] for key, values in fields.items() if values}

    def state_payload() -> dict:
        runtime = read_interface(interface, runner)
        settings = manager.settings()
        payload: dict = {
            "interface": interface,
            "conf_path": conf_path,
            "runtime": runtime.to_dict(redact=True),
            "peers": [peer.to_dict() for peer in manager.views(runtime)],
            "settings": settings.to_dict(),
            "settings_ready": settings.client_ready,
            "pending": None,
            "error": None,
        }
        raw = files.read_bytes(conf_path)
        if not raw:
            payload["error"] = f"{conf_path} does not exist"
            return payload
        try:
            plan = plan_change(target, raw, runner=runner)
        except WgPanelError as exc:
            payload["error"] = str(exc)
            return payload
        if plan.mode != "noop":
            payload["pending"] = {
                "mode": plan.mode,
                "steps": len(plan.steps),
                "changed_fields": plan.changed_fields,
                "peer_changes": plan.peer_changes.to_dict(),
                "destructive": plan.destructive,
                "disruptive": plan.disruptive,
                "warnings": plan.warnings,
            }
        return payload

    @api
    async def get_state(request) -> Response:
        return JSONResponse(state_payload())

    @api
    async def get_plan(request) -> Response:
        raw = files.read_bytes(conf_path)
        if not raw:
            raise WgPanelError(f"{conf_path} does not exist")
        return JSONResponse(plan_change(target, raw, runner=runner).to_dict())

    @api
    async def post_apply(request) -> Response:
        payload = await read_json(request)
        raw = files.read_bytes(conf_path)
        if not raw:
            raise WgPanelError(f"{conf_path} does not exist")
        result = apply(
            target,
            raw,
            runner=runner,
            allow_disruptive=bool(payload.get("allow_disruptive")),
            allow_destructive=bool(payload.get("allow_destructive")),
        )
        return JSONResponse(result.to_dict(), status_code=200 if result.ok else 500)

    @api
    async def get_settings(request) -> Response:
        return JSONResponse(manager.settings().to_dict())

    @api
    async def put_settings(request) -> Response:
        payload = await read_json(request)
        return JSONResponse(manager.update_settings(payload).to_dict())

    @api
    async def list_peers(request) -> Response:
        return JSONResponse({"peers": [peer.to_dict() for peer in manager.views()]})

    @api
    async def create_peer(request) -> Response:
        payload = await read_json(request)
        view, result = manager.add(
            str(payload.get("name", "")),
            keepalive=payload.get("keepalive"),
            extra_allowed_ips=payload.get("extra_allowed_ips") or [],
            apply_now=True,
        )
        return JSONResponse(
            {"peer": view.to_dict(), "apply": result.to_dict() if result else None},
            status_code=201 if (result is None or result.ok) else 500,
        )

    @api
    async def patch_peer(request) -> Response:
        payload = await read_json(request)
        name = request.path_params["name"]
        view, result = manager.update(
            name,
            name=payload.get("new_name"),
            allowed_ips=payload.get("allowed_ips"),
            keepalive=payload.get("keepalive", UNSET),
            endpoint=payload.get("endpoint", UNSET),
            apply_now=True,
        )
        return JSONResponse({"peer": view.to_dict(), "apply": result.to_dict() if result else None})

    @api
    async def delete_peer(request) -> Response:
        name = request.path_params["name"]
        result = manager.remove(name, apply_now=True)
        return JSONResponse({"removed": name, "apply": result.to_dict() if result else None})

    @api
    async def peer_conf(request) -> Response:
        name = request.path_params["name"]
        text = manager.client_conf(name)
        headers = {"Content-Disposition": f'attachment; filename="{name}.conf"'}
        return PlainTextResponse(text, headers=headers)

    @api
    async def peer_qr_svg(request) -> Response:
        name = request.path_params["name"]
        return Response(manager.client_qr_svg(name), media_type="image/svg+xml")

    @api
    async def peer_qr_png(request) -> Response:
        name = request.path_params["name"]
        return Response(manager.client_qr_png(name), media_type="image/png")

    @api
    async def health(request) -> Response:
        return JSONResponse({"ok": True, "interface": interface})

    async def login_page(request) -> Response:
        with open(os.path.join(STATIC_DIR, "login.html"), encoding="utf-8") as handle:
            return HTMLResponse(handle.read())

    async def post_login(request) -> Response:
        payload = await read_login(request)
        client = request.client.host if request.client else "unknown"

        # Checked before the password so that a locked-out address cannot get in
        # with the right one either.
        retry = guard.retry_after(client)
        if retry:
            return JSONResponse(
                {"error": f"登录失败次数太多，请 {retry} 秒后再试"},
                status_code=429,
                headers={"Retry-After": str(retry)},
            )

        token = guard.attempt(
            str(payload.get("user") or ""), str(payload.get("password") or ""), client
        )
        if token is None:
            return JSONResponse({"error": "账号或密码不对"}, status_code=401)

        response = JSONResponse({"ok": True, "user": guard.config.user})
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=guard.config.session_ttl,
            path="/",
            httponly=True,
            samesite="lax",
        )
        return response

    async def post_logout(request) -> Response:
        guard.sessions.drop(request.cookies.get(COOKIE_NAME))
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    async def index(request) -> Response:
        with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as handle:
            return HTMLResponse(handle.read())

    routes = [
        Route("/", index),
        Route("/login", login_page),
        Mount("/static", app=StaticFiles(directory=STATIC_DIR), name="static"),
        Route("/api/health", health),
        Route("/api/login", post_login, methods=["POST"]),
        Route("/api/logout", post_logout, methods=["POST"]),
        Route("/api/state", get_state),
        Route("/api/plan", get_plan),
        Route("/api/apply", post_apply, methods=["POST"]),
        Route("/api/settings", get_settings),
        Route("/api/settings", put_settings, methods=["PUT"]),
        Route("/api/peers", list_peers),
        Route("/api/peers", create_peer, methods=["POST"]),
        Route("/api/peers/{name}", patch_peer, methods=["PATCH"]),
        Route("/api/peers/{name}", delete_peer, methods=["DELETE"]),
        Route("/api/peers/{name}/conf", peer_conf),
        Route("/api/peers/{name}/qr.svg", peer_qr_svg),
        Route("/api/peers/{name}/qr.png", peer_qr_png),
    ]
    return Starlette(routes=routes, middleware=[Middleware(AuthMiddleware, guard=guard)])
