"""A Gateway build version, in either of IB's two spellings."""

from __future__ import annotations

import re
from dataclasses import dataclass

# The installer and image spelling: "10.50.1f" (the build letter is optional).
_DOTTED = re.compile(r"^(\d+)\.(\d+)\.(\d+)([a-z]?)$")
# The API's spelling, used in error 2172: "1050.1" means 10.50.1.
_COMPACT = re.compile(r"^(\d{3,4})\.(\d+)([a-z]?)$")


@dataclass(frozen=True, order=True)
class GatewayVersion:
    """Ordered by number, then build letter: a minimum of 10.50.1 is met by
    any 10.50.1 build, and 10.50.1f is newer than 10.50.1e."""

    major: int
    minor: int
    patch: int
    build: str = ""

    @classmethod
    def parse(cls, text: str) -> GatewayVersion:
        text = text.strip()
        if m := _DOTTED.match(text):
            return cls(int(m[1]), int(m[2]), int(m[3]), m[4])
        if m := _COMPACT.match(text):
            major, minor = divmod(int(m[1]), 100)
            return cls(major, minor, int(m[2]), m[3])
        raise ValueError(f"not a Gateway version: {text!r}")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}{self.build}"
