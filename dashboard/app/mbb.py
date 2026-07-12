"""Mnemonic Build Badge — spec v1 reference implementation.

Frozen wordlists + canonical derivation from the mnemonic-build-badge skill
(`~/Documents/SystemReference/skills/_universal/mnemonic-build-badge`). Any
implementation on any other language MUST produce identical output for the
same input; the test vectors in tests/test_mbb.py pin that contract.

Do NOT re-order or edit the wordlists — see the skill's "Extending the
keyspace" section. Adding words is a spec version bump.
"""

from __future__ import annotations

ADJECTIVES = [
    "amber", "azure", "coral", "crimson",
    "emerald", "golden", "indigo", "jade",
    "moss", "olive", "pearl", "ruby",
    "silver", "teal", "umber", "violet",
]

NOUNS = [
    "badger", "crane", "finch", "fox",
    "hare", "kite", "lynx", "moth",
    "otter", "panda", "quail", "raven",
    "salmon", "sparrow", "terrapin", "wren",
]

SPEC_VERSION = "v1"


def mbb(source_hex: str) -> str:
    """Return the two-word mnemonic for a hex source hash.

    Input is expected to be the first 7 chars of sha256(state) or the
    short-commit SHA. Longer inputs work; only low-order bits matter.
    """
    h = int(source_hex, 16)
    n_adj = len(ADJECTIVES)
    return f"{ADJECTIVES[h % n_adj]}-{NOUNS[(h // n_adj) % len(NOUNS)]}"
