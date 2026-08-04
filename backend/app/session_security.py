from __future__ import annotations

import secrets
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

COOKIE_NAME = "win_er_session"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
PROTECTED_GET_PATHS = {"/api/report/html"}


class LocalSessionMiddleware(BaseHTTPMiddleware):
    """Protect privileged localhost endpoints from remote and cross-site callers."""

    def __init__(self, app) -> None:
        super().__init__(app)
        self.token = secrets.token_urlsafe(32)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.hostname not in LOCAL_HOSTS:
            return JSONResponse({"detail": "Only local access is allowed"}, status_code=403)

        origin = request.headers.get("origin")
        if origin and urlparse(origin).hostname not in LOCAL_HOSTS:
            return JSONResponse({"detail": "Cross-site request rejected"}, status_code=403)

        protected = request.method not in {"GET", "HEAD", "OPTIONS"} or request.url.path in PROTECTED_GET_PATHS
        if request.url.path.startswith("/api/") and protected:
            supplied = request.cookies.get(COOKIE_NAME) or request.headers.get("x-er-session", "")
            if not secrets.compare_digest(supplied, self.token):
                return JSONResponse({"detail": "Invalid local session; refresh the page"}, status_code=403)

        if request.url.path == "/api/session":
            response = JSONResponse({"ok": True})
            response.set_cookie(COOKIE_NAME, self.token, httponly=True, samesite="strict", secure=False, path="/")
            return response
        return await call_next(request)
