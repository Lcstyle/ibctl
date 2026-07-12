"""Test vectors for the mnemonic-build-badge spec v1 implementation.

These MUST pass — they are the interop contract with any other language's
MBB implementation. Any mismatch means the modulo layering, wordlist
ordering, or hex parsing drifted.
"""

from __future__ import annotations

import pytest

from app.mbb import ADJECTIVES, NOUNS, SPEC_VERSION, mbb


class TestSpecInvariants:
    def test_wordlist_lengths_frozen(self):
        assert len(ADJECTIVES) == 16
        assert len(NOUNS) == 16

    def test_spec_version(self):
        assert SPEC_VERSION == "v1"

    def test_first_adjective_is_amber(self):
        # Load-bearing for the 00000000 test vector below.
        assert ADJECTIVES[0] == "amber"

    def test_first_noun_is_badger(self):
        assert NOUNS[0] == "badger"


class TestSpecTestVectors:
    """From SKILL.md — mismatch here means implementation is wrong."""

    @pytest.mark.parametrize("source_hex,expected", [
        ("00000000", "amber-badger"),
        ("0000000f", "violet-badger"),
        ("00000010", "amber-crane"),
        ("0e586f3", "crimson-wren"),
        ("b1f8070", "amber-moth"),
        ("48f731b", "ruby-crane"),
        ("ffffffff", "violet-wren"),
    ])
    def test_canonical_vectors(self, source_hex: str, expected: str):
        assert mbb(source_hex) == expected


class TestDeterminism:
    def test_same_input_same_output(self):
        assert mbb("deadbee") == mbb("deadbee")

    def test_bit_change_flips_at_least_one_word(self):
        # Per spec: dividing by len(ADJECTIVES) before the second modulo
        # means the noun is picked from a different bit region than the
        # adjective. A one-bit change almost always flips at least one word.
        a = mbb("0000000")
        b = mbb("0000001")
        assert a != b
