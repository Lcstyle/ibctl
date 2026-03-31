"""Bearer token authentication middleware.

When IBCTL_DASHBOARD_TOKEN is set (non-empty), all requests except static
files must include a valid Authorization: Bearer <token> header.
When the token is empty, all requests pass through (open access).
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Enforce Bearer token auth when a dashboard token is configured."""

    async def dispatch(self, request: Request, call_next):
        token = request.app.state.settings.token

        # No token configured — open access
        if not token:
            return await call_next(request)

        # Static files bypass auth (CSS, JS, images)
        if request.url.path.startswith("/static"):
            return await call_next(request)

        # Validate Bearer token
        auth_header = request.headers.get("Authorization", "")
        if auth_header == f"Bearer {token}":
            return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
            headers={"WWW-Authenticate": "Bearer"},
        )
