"""API access: named API tokens, their types and the warm-restart limiter state.

Everything is saved in one file, `api_access.json`, under the persist
directory's `config/` folder, next to the dashboard's other saved settings.

A token is a random secret shown once, when it is created. Only its SHA-256 is
kept, so the file cannot be turned back into a working token. The secret has
256 bits of entropy, so a plain unsalted hash is enough; the lookup compares
the hash of what a client sent against every stored hash in constant time.

A token has a type, chosen when it is created. A type (`TOKEN_TYPES`, the one
table) is a fixed bundle of routes, and a token reaches only the routes of its
own type. The operator can also switch a whole type off on the API access page:
a type must be enabled for its tokens to work. A token is never a login: the
auth middleware admits a recognised token only to those routes.

A file saved before types existed has tokens with no `type` (they are warm
restart tokens) and a tick list keyed by command name (`allowed`). It loads as
is, and the next save writes it in the current shape.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

logger = logging.getLogger("dashboard.api_access")

DEFAULT_PATH = Path(os.environ.get("IBCTL_PERSIST_DIR", "/opt/ibctl/persist")) / "config" / "api_access.json"

# Instances the per-mode settings are kept for.
MODES = ("live", "paper")

TOKEN_PREFIX = "ibctl_"
_TOKEN_BYTES = 32
_MAX_PRESENTED_LENGTH = 256
_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

DEFAULT_INTERVAL_MINUTES = 30
MIN_INTERVAL_MINUTES = 1
MAX_INTERVAL_MINUTES = 24 * 60

_FILE_VERSION = 2


@dataclass(frozen=True)
class TokenType:
    """One kind of API token: the routes it opens and whether it is on until the operator says so."""

    name: str  # what the file and the form carry
    label: str
    description: str
    routes: tuple[tuple[str, str], ...]  # (METHOD, path): exactly what a token of this type may call
    # What the dashboard sends ibctl for it, when it sends one; ibctl's own allow-list gates that.
    ibctl_command: str | None = None
    default_enabled: bool = False


# The one table. To add a type, add an entry: the page, the checks and the sweep tests read it.
TOKEN_TYPES: tuple[TokenType, ...] = (
    TokenType(
        name="warm_restart",
        label="Warm restart client",
        description=(
            "Restart a Gateway now, reusing its saved session so it needs no 2FA. "
            "Also lets the token read that mode's last outcome."
        ),
        routes=(("POST", "/api/v1/warm-restart"), ("GET", "/api/v1/warm-restart")),
        ibctl_command="SETRESTART",
        default_enabled=True,
    ),
    TokenType(
        name="upgrade_ci",
        label="Gateway upgrade: CI",
        description=(
            "CI reports the image it built for a Gateway version, which steers the image the Sunday swap "
            "uses, and reads the upgrade state. Off until enabled."
        ),
        routes=(("GET", "/api/v1/gateway/upgrade"), ("POST", "/api/v1/gateway/upgrade/candidate")),
    ),
    TokenType(
        name="upgrade_maintenance",
        label="Gateway upgrade: maintenance",
        description=(
            "The Sunday maintenance job reads the swap plan and reports what its swap did "
            "(shown on the Gateway page, it changes nothing). Off until enabled."
        ),
        routes=(("GET", "/api/v1/gateway/upgrade"), ("POST", "/api/v1/gateway/upgrade/swap")),
    ),
)

# A token saved with no type is a warm restart token: that was the only kind.
DEFAULT_TYPE = "warm_restart"

# What an earlier build ticked, by the name of the command, and the type that replaces it.
_LEGACY_TICKS = {"WARMRESTART": "warm_restart"}


def find_token_type(name: object) -> TokenType | None:
    """The type called `name`, or None."""
    return next((t for t in TOKEN_TYPES if t.name == name), None)


class TokenError(ValueError):
    """A token name is not acceptable (invalid or already taken)."""


class ApiAccessError(RuntimeError):
    """The saved API-access file cannot be read, so nothing is changed or trusted."""


@dataclass(frozen=True)
class ApiToken:
    name: str
    created_at: float
    created_by: str
    type: str = DEFAULT_TYPE  # a name from TOKEN_TYPES, or one this build does not know (it opens nothing)


def hash_token(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def validate_token_name(name: str) -> str:
    name = name.strip()
    if not _NAME_PATTERN.fullmatch(name):
        raise TokenError(
            "A token name is 1 to 64 letters, digits, dots, dashes or underscores, "
            "starting with a letter or digit."
        )
    return name


class ApiAccessStore:
    """The saved API-access state. Every read goes to the file, so another
    process or a restart sees the same thing; every write replaces it whole."""

    def __init__(self, path: Path = DEFAULT_PATH, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()

    # --- the file ---

    def _load(self) -> dict:
        try:
            text = self.path.read_text()
        except FileNotFoundError:
            return {}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ApiAccessError(f"{self.path} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ApiAccessError(f"{self.path} does not hold an object")
        return data

    def _save(self, data: dict) -> None:
        data["version"] = _FILE_VERSION
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)

    @staticmethod
    def _migrate(data: dict) -> None:
        """Bring a file an earlier build saved to the current shape, in place.

        Every token gets the `type` it was always implicitly given, and the tick
        list keyed by command name (`allowed`) becomes `enabled_types`. Anything
        else in the file, including keys this build does not know, is left alone.
        """
        for entry in ApiAccessStore._entries(data):
            entry.setdefault("type", DEFAULT_TYPE)
        if "allowed" in data:
            data.setdefault("enabled_types", sorted(ApiAccessStore._enabled(data)))
            del data["allowed"]

    def _update(self, change: Callable[[dict], object]):
        """Read, bring to the current shape, apply `change`, write. Returns what `change` returns."""
        with self._lock:
            data = self._load()
            self._migrate(data)
            result = change(data)
            self._save(data)
            return result

    # --- tokens ---

    @staticmethod
    def _entries(data: dict) -> list[dict]:
        entries = data.get("tokens", [])
        return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []

    @staticmethod
    def _token(entry: dict) -> ApiToken:
        saved = entry.get("type")
        return ApiToken(
            str(entry.get("name", "")),
            float(entry.get("created_at", 0)),
            str(entry.get("created_by", "")),
            saved if isinstance(saved, str) and saved else DEFAULT_TYPE,
        )

    def list_tokens(self) -> list[ApiToken]:
        return [self._token(e) for e in self._entries(self._load())]

    def create_token(self, name: str, created_by: str, token_type: str = DEFAULT_TYPE) -> tuple[ApiToken, str]:
        """Save a new token of `token_type` and return it with its secret. The secret is not kept."""
        name = validate_token_name(name)
        if find_token_type(token_type) is None:
            raise TokenError(
                f"{token_type!r} is not a token type. Choose one of: {', '.join(t.name for t in TOKEN_TYPES)}."
            )
        secret = TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)
        token = ApiToken(name, self._clock(), created_by, token_type)

        def add(data: dict) -> None:
            entries = self._entries(data)
            if any(e.get("name", "").casefold() == name.casefold() for e in entries):
                raise TokenError(f"A token named {name!r} already exists.")
            entries.append(
                {
                    "name": name,
                    "type": token_type,
                    "hash": hash_token(secret),
                    "created_at": token.created_at,
                    "created_by": created_by,
                }
            )
            data["tokens"] = entries

        self._update(add)
        return token, secret

    def revoke_token(self, name: str) -> bool:
        def drop(data: dict) -> bool:
            entries = self._entries(data)
            kept = [e for e in entries if e.get("name") != name]
            data["tokens"] = kept
            return len(kept) != len(entries)

        return self._update(drop)

    def recognise(self, presented: str) -> ApiToken | None:
        """The token a client's secret belongs to, or None. Never raises."""
        if not presented or len(presented) > _MAX_PRESENTED_LENGTH:
            return None
        try:
            entries = self._entries(self._load())
        except ApiAccessError:
            logger.error("API access file is unreadable; no API token is recognised until it is fixed")
            return None
        digest = hash_token(presented).encode("ascii")
        match = None
        for entry in entries:  # compare them all: how long it takes says nothing about which matched
            stored = str(entry.get("hash", "")).encode("utf-8", "replace")
            if hmac.compare_digest(stored, digest):
                match = entry
        return None if match is None else self._token(match)

    # --- which types are on ---

    @staticmethod
    def _enabled(data: dict) -> frozenset[str]:
        """The enabled types in `data`: the saved list, else what an earlier build ticked, else the defaults."""
        known = {t.name for t in TOKEN_TYPES}
        saved = data.get("enabled_types")
        if isinstance(saved, list):
            return frozenset(str(name) for name in saved if name in known)
        legacy = data.get("allowed")
        if isinstance(legacy, list):
            by_type = {new: old for old, new in _LEGACY_TICKS.items()}
            return frozenset(
                t.name for t in TOKEN_TYPES if (by_type[t.name] in legacy if t.name in by_type else t.default_enabled)
            )
        return frozenset(t.name for t in TOKEN_TYPES if t.default_enabled)

    def enabled_types(self) -> frozenset[str]:
        return self._enabled(self._load())

    def is_enabled(self, type_name: str) -> bool:
        """Whether tokens of this type work. An unreadable file enables nothing."""
        try:
            return type_name in self.enabled_types()
        except ApiAccessError:
            logger.error("API access file is unreadable; treating every token type as disabled")
            return False

    def set_enabled(self, names: Iterable[str]) -> None:
        chosen = sorted(set(names))
        unknown = [n for n in chosen if find_token_type(n) is None]
        if unknown:
            raise ValueError(f"not a token type: {', '.join(unknown)}")
        self._update(lambda data: data.__setitem__("enabled_types", chosen))

    # --- per-mode settings and state ---

    def min_interval_minutes(self, mode: str) -> int:
        saved = self._load().get("min_interval_minutes")
        value = saved.get(mode) if isinstance(saved, dict) else None
        if isinstance(value, int) and not isinstance(value, bool) and MIN_INTERVAL_MINUTES <= value <= MAX_INTERVAL_MINUTES:
            return value
        return DEFAULT_INTERVAL_MINUTES

    def set_min_interval_minutes(self, minutes: dict[str, int]) -> None:
        for mode, value in minutes.items():
            if mode not in MODES:
                raise ValueError(f"not a mode: {mode!r}")
            if not isinstance(value, int) or isinstance(value, bool) or not MIN_INTERVAL_MINUTES <= value <= MAX_INTERVAL_MINUTES:
                raise ValueError(
                    f"the minimum interval is a whole number of minutes from {MIN_INTERVAL_MINUTES} "
                    f"to {MAX_INTERVAL_MINUTES}, not {value!r}"
                )

        def save(data: dict) -> None:
            current = data.get("min_interval_minutes")
            merged = dict(current) if isinstance(current, dict) else {}
            merged.update(minutes)
            data["min_interval_minutes"] = merged

        self._update(save)

    def warm_restart_record(self, mode: str) -> dict | None:
        """The last accepted warm restart for `mode`, or None if there never was one."""
        records = self._load().get("warm_restart")
        record = records.get(mode) if isinstance(records, dict) else None
        return dict(record) if isinstance(record, dict) else None

    def save_warm_restart_record(self, mode: str, record: dict | None) -> None:
        """Save (or, with None, clear) the last accepted warm restart for `mode`."""

        def save(data: dict) -> None:
            records = data.get("warm_restart")
            records = dict(records) if isinstance(records, dict) else {}
            if record is None:
                records.pop(mode, None)
            else:
                records[mode] = record
            data["warm_restart"] = records

        self._update(save)
