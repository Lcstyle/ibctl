"""URLs the dashboard hands back to a browser, as paths under the proxy prefix.

A reverse proxy may publish the dashboard under a path (nginx serves it at
`/ibctl/` and strips that prefix before forwarding), so the app sees `/config`
while the browser asked for `/ibctl/config`. IBCTL_ROOT_PATH carries the prefix.
Anything the browser follows or stores has to include it: redirects, and the
path of the cookies it is allowed to send back. Paths only, never an absolute
URL, because the scheme and host the app sees are the proxy's, not the visitor's.
"""

from __future__ import annotations

from starlette.requests import HTTPConnection


def root_path(connection: HTTPConnection) -> str:
    """The proxy prefix with no trailing slash, or "" when the app is served at the site root."""
    templates = getattr(connection.app.state, "templates", None)
    prefix = templates.env.globals.get("root_path", "") if templates is not None else ""
    return (prefix or "").rstrip("/")


def app_url(connection: HTTPConnection, path: str) -> str:
    """`path` (an app-internal path such as "/config?x=1") as the browser must request it."""
    return f"{root_path(connection)}{path}"


def cookie_path(connection: HTTPConnection) -> str:
    """The Path a cookie is scoped to: the dashboard's own prefix, not every app on the site."""
    return root_path(connection) or "/"


def legacy_cookie_paths(connection: HTTPConnection) -> list[str]:
    """Paths an earlier build set the dashboard's cookies at, to clear on login and logout.

    Before the proxy prefix was honoured every cookie was set at `Path=/`. With a
    prefix, a browser that still holds one of those would send it alongside the
    new one.
    """
    return ["/"] if root_path(connection) else []
