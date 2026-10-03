"""HTTP API and web UI."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .. import files
from ..apply import apply
from ..differ import Target, plan_change
from ..errors import RiskGateError, ValidationError, WgPanelError
from ..peers import UNSET, KeySource, PeerManager
from ..runner import LocalRunner, Runner
from ..runtime import read_interface

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def create_app(
    *,
    interface: str,
    conf_path: str,
    state_dir: str,
    config_dir: str = "",
    runner: Runner | None = None,
    keys: KeySource | None = None,
) -> Starlette:
    runner = runner or LocalRunner()
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
            import json

            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise WgPanelError(f"invalid JSON body: {exc}") from None
        return payload if isinstance(payload, dict) else {}

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

    async def index(request) -> Response:
        with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as handle:
            return HTMLResponse(handle.read())

    routes = [
        Route("/", index),
        Mount("/static", app=StaticFiles(directory=STATIC_DIR), name="static"),
        Route("/api/health", health),
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
    return Starlette(routes=routes)
