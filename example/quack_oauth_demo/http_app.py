"""aiohttp front-end: static client, GitHub OAuth handler, /quack proxy.

The aiohttp app is the SINGLE origin the browser talks to. The quack
HTTP listener is bound to 127.0.0.1 on a random port and is reachable
ONLY through this app's `/quack` reverse-proxy route. That gives us:

  1. A predictable port for the OAuth redirect URI.
  2. One place to attach COOP / COEP / CORP headers, which together
     enable `crossOriginIsolated = true` in the browser -- the
     prerequisite for SharedArrayBuffer-backed zero-copy Arrow IPC
     between the DuckDB-Wasm heap and the Perspective WASM heap.
  3. A natural CSRF defence on the OAuth `state` parameter.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import aiohttp
from aiohttp import web

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
# OAuth Web Flow user-to-server tokens carry `repo` by default; the
# server-side policy grants Attach + Scan to any token with that scope.
OAUTH_SCOPE = "read:user"
STATE_TTL_S = 300


@dataclass
class AppConfig:
    github_client_id: str
    github_client_secret: str
    redirect_uri: str
    quack_port: int


# -- middleware: cross-origin isolation headers --------------------------------

@web.middleware
async def coop_coep_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    """Set COOP/COEP/CORP on every response so the page runs in a
    cross-origin-isolated context (`window.crossOriginIsolated === true`).

    Without this, `SharedArrayBuffer` is unavailable in the browser and
    the Arrow IPC handoff between DuckDB-Wasm and Perspective falls
    back to a memcpy between heaps. Still fast, but not the
    headline-grabbing zero-copy path.
    """
    resp: web.StreamResponse = await handler(request)
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    return resp


# -- static + OAuth handlers ---------------------------------------------------

async def index(request: web.Request) -> web.FileResponse:
    return web.FileResponse(STATIC_DIR / "index.html")


async def oauth_login(request: web.Request) -> web.Response:
    cfg: AppConfig = request.app["cfg"]
    state = secrets.token_urlsafe(24)
    request.app["oauth_state"][state] = time.time()
    params = {
        "client_id": cfg.github_client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": OAUTH_SCOPE,
        "state": state,
        "allow_signup": "false",
    }
    return web.HTTPFound(f"{GITHUB_AUTH_URL}?{urlencode(params)}")


async def oauth_callback(request: web.Request) -> web.Response:
    cfg: AppConfig = request.app["cfg"]
    code = request.query.get("code")
    state = request.query.get("state")
    if not code or not state:
        return web.Response(status=400, text="missing code or state")

    # Drop expired states + reject unknown/stale ones (CSRF defence).
    states: dict[str, float] = request.app["oauth_state"]
    now = time.time()
    for k in list(states):
        if now - states[k] > STATE_TTL_S:
            del states[k]
    if states.pop(state, None) is None:
        return web.Response(status=400, text="unknown or stale state")

    body = {
        "client_id": cfg.github_client_id,
        "client_secret": cfg.github_client_secret,
        "code": code,
        "redirect_uri": cfg.redirect_uri,
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            GITHUB_TOKEN_URL,
            data=body,
            headers={"Accept": "application/json"},
        ) as r:
            payload = await r.json()
    token = payload.get("access_token")
    if not token:
        return web.Response(
            status=400, text=f"github did not return access_token: {payload}"
        )

    # Land the token in sessionStorage and bounce back to /. The
    # wasm client reads it from there and embeds it in the ATTACH SQL.
    html = (
        "<!doctype html><meta charset='utf-8'><title>OAuth callback</title>"
        "<script>"
        f"sessionStorage.setItem('gh_token', {token!r});"
        "location.replace('/');"
        "</script>"
    )
    return web.Response(text=html, content_type="text/html")


# -- /quack reverse proxy ------------------------------------------------------

async def quack_proxy(request: web.Request) -> web.StreamResponse:
    """Forward POST /quack to the internal quack listener.

    Quack's response body is a binary Arrow IPC payload streamed
    through `http.server`'s `Content-Length`-known reply (see
    duckdb-quack `quack_http_server.cpp`). We forward the raw bytes
    with content-type preserved and drop hop-by-hop headers.
    """
    cfg: AppConfig = request.app["cfg"]
    upstream_url = f"http://127.0.0.1:{cfg.quack_port}/quack"

    body = await request.read()
    # Don't forward the Host header (would point at the upstream's
    # 127.0.0.1) or hop-by-hop headers.
    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {"host", "content-length", "connection"}
    }

    session: aiohttp.ClientSession = request.app["client_session"]
    async with session.post(upstream_url, data=body, headers=fwd_headers) as up:
        resp = web.StreamResponse(status=up.status)
        for h in ("content-type", "content-encoding"):
            if h in up.headers:
                resp.headers[h] = up.headers[h]
        # Same-origin already (page and /quack on the same aiohttp port),
        # but be explicit for the COEP precondition.
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        await resp.prepare(request)
        async for chunk in up.content.iter_any():
            await resp.write(chunk)
        await resp.write_eof()
        return resp


async def quack_options(request: web.Request) -> web.Response:
    # Defensive: same-origin so no preflight should actually fire.
    return web.Response(status=204)


# -- /ext-repo reverse proxy: CORS-injected mirror of get.erpl.io --------------

EXT_UPSTREAM = "http://get.erpl.io"


async def ext_repo_proxy(request: web.Request) -> web.StreamResponse:
    """Same-origin mirror of get.erpl.io, with CORS headers added.

    DuckDB-Wasm fetches extension binaries via XHR. The bucket at
    get.erpl.io (the same one we publish quack_oauth artefacts to)
    does NOT emit `Access-Control-Allow-Origin`, so a direct
    `INSTALL quack_oauth FROM 'http://get.erpl.io'` from the browser
    fails. The bucket-side fix is an `aws s3api put-bucket-cors`
    config -- out of scope for the demo. Instead we serve a
    same-origin pass-through that injects ACAO + ACAM headers.

    Path shape DuckDB-Wasm builds: `<from>/<duckdb_ver>/<arch>/<ext>.duckdb_extension.wasm`.
    Client does `INSTALL quack_oauth FROM 'http://localhost:<p>/ext-repo';`
    and we forward to `http://get.erpl.io/<rest>`.
    """
    tail = request.match_info["tail"]
    upstream_url = f"{EXT_UPSTREAM}/{tail}"

    session: aiohttp.ClientSession = request.app["client_session"]
    async with session.get(upstream_url) as up:
        resp = web.StreamResponse(status=up.status)
        for h in ("content-type", "content-length", "content-encoding", "etag", "last-modified"):
            if h in up.headers:
                resp.headers[h] = up.headers[h]
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, HEAD, OPTIONS"
        resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        await resp.prepare(request)
        async for chunk in up.content.iter_any():
            await resp.write(chunk)
        await resp.write_eof()
        return resp


async def ext_repo_options(request: web.Request) -> web.Response:
    return web.Response(
        status=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
            "Access-Control-Max-Age": "3600",
        },
    )


# -- app factory + runner ------------------------------------------------------

async def _on_startup(app: web.Application) -> None:
    # auto_decompress=False so brotli/gzip bodies stream through to the
    # browser intact (the browser decodes them natively, and we avoid
    # an optional Brotli python dep). Critical for the /ext-repo
    # proxy: get.erpl.io serves the .duckdb_extension.wasm with
    # `Content-Encoding: br`.
    app["client_session"] = aiohttp.ClientSession(auto_decompress=False)


async def _on_cleanup(app: web.Application) -> None:
    await app["client_session"].close()


def build_app(cfg: AppConfig) -> web.Application:
    app = web.Application(middlewares=[coop_coep_middleware])
    app["cfg"] = cfg
    app["oauth_state"] = {}
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    app.router.add_get("/", index)
    app.router.add_get("/oauth/login", oauth_login)
    app.router.add_get("/oauth/callback", oauth_callback)
    app.router.add_options("/quack", quack_options)
    app.router.add_post("/quack", quack_proxy)
    app.router.add_options("/ext-repo/{tail:.*}", ext_repo_options)
    app.router.add_get("/ext-repo/{tail:.*}", ext_repo_proxy)
    app.router.add_static("/static/", path=STATIC_DIR, name="static")
    return app


def run(port: int, cfg: AppConfig) -> None:
    web.run_app(
        build_app(cfg),
        host="127.0.0.1",
        port=port,
        access_log=log,
        print=lambda *_: None,
    )
