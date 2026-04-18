"""Auth0 integration for FastAPI — middleware, routes, and setup."""

from __future__ import annotations

import os
from urllib.parse import quote_plus

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware


def _build_oauth() -> OAuth:
    oauth = OAuth()
    oauth.register(
        "auth0",
        client_id=os.environ["AUTH0_CLIENT_ID"],
        client_secret=os.environ["AUTH0_CLIENT_SECRET"],
        server_metadata_url=(
            f'https://{os.environ["AUTH0_DOMAIN"]}/.well-known/openid-configuration'
        ),
        client_kwargs={"scope": "openid profile email"},
    )
    return oauth


def _build_router(oauth: OAuth) -> APIRouter:
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.get("/login")
    async def login(request: Request):
        callback_url = str(request.url_for("auth_callback"))
        return await oauth.auth0.authorize_redirect(request, callback_url)

    @router.get("/callback", name="auth_callback")
    async def callback(request: Request):
        token = await oauth.auth0.authorize_access_token(request)
        request.session["user"] = token["userinfo"]
        return RedirectResponse(url="/")

    @router.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        domain = os.environ["AUTH0_DOMAIN"]
        client_id = os.environ["AUTH0_CLIENT_ID"]
        # Build the base URL (scheme + host) for the return-to parameter
        base_url = str(request.base_url).rstrip("/")
        return_to = quote_plus(base_url)
        logout_url = (
            f"https://{domain}/v2/logout"
            f"?client_id={client_id}"
            f"&returnTo={return_to}"
        )
        return RedirectResponse(url=logout_url)

    return router


def _auth_middleware_factory(
    skip_prefixes: tuple[str, ...],
):
    """Return an ASGI middleware callable that enforces login."""

    async def auth_middleware(request: Request, call_next):
        if any(request.url.path.startswith(p) for p in skip_prefixes):
            return await call_next(request)

        user = request.session.get("user")
        if user:
            return await call_next(request)

        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        return RedirectResponse(url="/auth/login")

    return auth_middleware


def require_login(request: Request) -> dict:
    """FastAPI dependency — returns the session user dict or raises 401.

    Use this when you need the user object in a route handler:

        @app.get("/profile")
        def profile(user: dict = Depends(require_login)):
            return user
    """
    user = request.session.get("user")
    if not user:
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def init_auth(
    app: FastAPI,
    skip_prefixes: tuple[str, ...] = ("/auth/", "/static/"),
) -> None:
    """Wire up Auth0 authentication on a FastAPI app.

    Call this once in your main.py:

        from starrstack_auth import init_auth
        init_auth(app)

    Requires these environment variables:
        AUTH0_CLIENT_ID
        AUTH0_CLIENT_SECRET
        AUTH0_DOMAIN
        APP_SECRET_KEY

    Args:
        app: The FastAPI application instance.
        skip_prefixes: URL prefixes that bypass auth (default: /auth/, /static/).
    """
    secret_key = os.environ["APP_SECRET_KEY"]

    oauth = _build_oauth()
    router = _build_router(oauth)
    app.include_router(router)
    app.middleware("http")(_auth_middleware_factory(skip_prefixes))

    # SessionMiddleware must be added last — Starlette processes middleware
    # LIFO, so last-added is outermost and runs first, ensuring
    # request.session is available when the auth middleware executes.
    app.add_middleware(SessionMiddleware, secret_key=secret_key)
