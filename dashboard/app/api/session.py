"""The browser's session keep-alive.

A page sends `POST /api/session/touch` while its user is active. Like any
request that is not a GET, it counts as user activity, so the auth middleware
refreshes the session cookie on the way out; the handler has nothing left to
do. It needs a login (it is not on the public list and not a token route), so
an anonymous caller, an API token alone and an idle-expired session all get the
usual 401.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

from app.middleware.auth import SESSION_TOUCH_PATH

router = APIRouter()


@router.post(SESSION_TOUCH_PATH, status_code=204, include_in_schema=False)
async def touch() -> Response:
    return Response(status_code=204)
