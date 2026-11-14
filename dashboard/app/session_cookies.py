"""Signed cookie values: the one place the dashboard builds and reads them.

A value is a small JSON object signed with `itsdangerous` (the library
Starlette's own session middleware uses), HMAC-SHA256 under the dashboard's
signing secret. Each kind of cookie has its own salt, so a value signed for one
kind does not validate as another even though they share a secret: an OAuth
state (handed to anyone who starts a login) is not a session, and a password
session is not an OAuth session.

Only the signature is checked here. What a payload claims (`iat`, `act`, `auth`,
`login`, the age limits) is the caller's to check: see `app.middleware.auth`.

The format changed when this module replaced the earlier hand-rolled one
(base64 JSON plus a hex HMAC). An old cookie no longer validates, so everyone
signs in once after the upgrade.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from itsdangerous import BadData, URLSafeSerializer


class Kind(Enum):
    """A kind of signed cookie. Its salt keeps it apart from every other kind."""

    PASSWORD_SESSION = "password-session"  # nosecret: a cookie kind, not a secret
    OAUTH_SESSION = "oauth-session"
    OAUTH_STATE = "oauth-state"

    @property
    def salt(self) -> str:
        return f"ibctl-dashboard:{self.value}"


def _serializer(kind: Kind, secret: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret, salt=kind.salt, signer_kwargs={"digest_method": hashlib.sha256})


def sign(kind: Kind, payload: dict, secret: str) -> str:
    """`payload` as a cookie-safe signed string of this kind."""
    return _serializer(kind, secret).dumps(payload)


def unsign(kind: Kind, value: str, secret: str) -> dict | None:
    """The payload of a value signed as `kind` under `secret`, or None for anything else. Never raises.

    An empty secret verifies nothing: a dashboard with no login configured has no
    signing secret, and a value forged with an empty key must not pass.
    """
    if not secret:
        return None
    try:
        payload = _serializer(kind, secret).loads(value)
    except BadData:
        return None
    return payload if isinstance(payload, dict) else None
