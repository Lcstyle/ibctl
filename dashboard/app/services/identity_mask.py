"""Keep the IB login name and account numbers out of what the dashboard shows.

A person who is logged in may read the Config page and the config JSON, but
the name the Gateway logs in with is not theirs to see: those views say
"set" or "not set" instead. Every path that carries ibctl's configuration to
a response (the local ibctl.toml with its env overrides, and ibctl's CONFIG
reply) goes through `mask_identity`, so a template or route added later gets
the same treatment without remembering to.

Two rules, applied at any depth:
- a key that holds a login name (`tws_userid`, `tws_userid_paper`, `username`)
  has its value replaced by "set" or "not set";
- a string that contains something shaped like an IB account number
  (DU1234567, U1234567, ...) has that part replaced.
"""

from __future__ import annotations

import re
from typing import Any

SET = "set"
NOT_SET = "not set"
ACCOUNT_PLACEHOLDER = "[account]"

# IB account numbers: a one- or two-letter prefix (live U, paper DU, advisor
# and friends F/DF/I/DI) and six to nine digits.
_ACCOUNT_SHAPE = re.compile(r"\b(?:DU|DF|DI|U|F|I)\d{6,9}\b")


def _holds_login_name(key: str) -> bool:
    key = key.lower()
    return "userid" in key or key in {"username", "user_name"}


def mask_identity(node: Any) -> Any:
    """A copy of `node` (parsed config) with login names and account numbers hidden."""
    if isinstance(node, dict):
        return {
            key: (SET if value else NOT_SET) if isinstance(key, str) and _holds_login_name(key) else mask_identity(value)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [mask_identity(item) for item in node]
    if isinstance(node, str):
        return _ACCOUNT_SHAPE.sub(ACCOUNT_PLACEHOLDER, node)
    return node
