"""Extract ``/// ...`` doc comments from ``config/pkl/types.pkl``.

The extractor walks the file line-by-line and returns a
``{ClassName: {fieldName: FieldDoc}}`` mapping. Each ``FieldDoc`` bundles the
descriptive ``///`` prose block that immediately precedes a field declaration
and (if present) the ``@env`` annotation name.

``@env`` annotation lines (e.g. ``/// @env TWS_USERID``) are considered
structural, not descriptive. We track them separately from the prose so
downstream renderers can decide how to surface them (a trailing
``# @env: FOO`` comment on the emitted TOML, an ``(env: FOO)`` suffix on the
dashboard tooltip, or drop them entirely). Blank ``///`` lines inside the
prose block are preserved (they become paragraph breaks in rendered TOML).

Because ``config/pkl/types.pkl`` is entirely hand-authored — no nested classes,
class bodies are the only balanced-brace regions we care about, and every
field is declared at a single indent level — a lightweight regex scanner
tracking brace depth is sufficient. We deliberately avoid pulling in the Pkl
runtime here: this scanner runs during ``check-configs`` in CI where the Pkl
CLI is intentionally absent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_CLASS_RE = re.compile(r"^class\s+([A-Z][A-Za-z0-9_]*)\s*\{")
_FIELD_RE = re.compile(r"^\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*")
_DOC_RE = re.compile(r"^\s*///\s?(.*)$")
_ENV_RE = re.compile(r"^@env\s+([A-Z][A-Z0-9_]*)")


@dataclass
class FieldDoc:
    """Descriptive ``///`` block + optional ``@env`` annotation for one field."""

    lines: list[str] = field(default_factory=list)
    env: str | None = None


def extract_pkl_docs(path: Path) -> dict[str, dict[str, FieldDoc]]:
    """Return ``{className: {fieldName: FieldDoc}}`` for every class.

    Doc lines are the exact text after ``/// `` (or ``///``), trailing
    whitespace trimmed; leading whitespace kept so lists/indented sub-bullets
    survive round-trip. ``@env`` annotation lines are stripped from the prose
    and captured into ``FieldDoc.env``.
    """
    text = Path(path).read_text()
    lines = text.splitlines()

    docs: dict[str, dict[str, FieldDoc]] = {}
    current_class: str | None = None
    depth = 0
    prose: list[str] = []
    env_name: str | None = None

    for raw in lines:
        stripped = raw.strip()

        # Class open — only at depth 0 (no nested classes in types.pkl).
        cm = _CLASS_RE.match(raw)
        if cm and depth == 0:
            current_class = cm.group(1)
            docs.setdefault(current_class, {})
            depth = 1  # opening brace consumed by the regex
            prose = []
            env_name = None
            continue

        # Doc comment line.
        dm = _DOC_RE.match(raw)
        if dm:
            content = dm.group(1).rstrip()
            env_match = _ENV_RE.match(content)
            if env_match:
                # Structural annotation — captured, not treated as prose.
                env_name = env_match.group(1)
                continue
            prose.append(content)
            continue

        # Inside a class — try to attach the accumulated buffer to a field.
        if current_class is not None and depth >= 1:
            # Update brace depth using this line's punctuation (but only outside
            # of strings — types.pkl has no braces inside strings today, so a
            # naive count is safe).
            depth += raw.count("{") - raw.count("}")
            if depth <= 0:
                # We just closed the class body.
                current_class = None
                prose = []
                env_name = None
                depth = 0
                continue

            fm = _FIELD_RE.match(raw)
            if fm:
                field_name = fm.group(1)
                if prose or env_name:
                    docs[current_class][field_name] = FieldDoc(
                        lines=prose, env=env_name
                    )
                prose = []
                env_name = None
                continue

            # Any other non-blank, non-doc line breaks the buffer.
            if stripped:
                prose = []
                env_name = None
            continue

        # Outside any class — reset the buffer on non-doc content.
        if stripped and not stripped.startswith("///"):
            prose = []
            env_name = None

    return docs


def lookup(
    docs: dict[str, dict[str, FieldDoc]], class_name: str, field_name: str
) -> FieldDoc:
    """Return the ``FieldDoc`` for ``class_name.field_name`` — empty if absent."""
    return docs.get(class_name, {}).get(field_name, FieldDoc())


def join_description(doc: FieldDoc | list[str]) -> str:
    """Collapse a doc block into a single-line description string.

    Used for JSON output and HTML tooltips. Preserves paragraph breaks in
    multi-line blocks by joining with a single space and squashing runs of
    whitespace — the tooltip is expected to be a single line at the UI layer.

    If a ``FieldDoc`` with an ``env`` annotation is passed, an
    ``(env: FOO)`` suffix is appended to the joined prose so operators
    reading the tooltip can still discover the canonical env-var name.

    Accepts a plain ``list[str]`` for backward compatibility with call sites
    that only carry prose lines (no ``@env`` context available).
    """
    if isinstance(doc, FieldDoc):
        lines = doc.lines
        env = doc.env
    else:
        lines = doc
        env = None

    if not lines and not env:
        return ""
    if lines:
        text = " ".join(line.strip() for line in lines if line.strip())
        text = re.sub(r"\s+", " ", text).strip()
    else:
        text = ""
    if env:
        suffix = f"(env: {env})"
        text = f"{text} {suffix}".strip()
    return text
