"""
Tests for Binlex Tool Runner and Genetic Trait Matcher (src/tools/binlex_runner.py).
Failure Modes Covered:
- FM-BLX-R01: Non-existent target binary
- FM-BLX-R02: DB file missing or empty during matching
- FM-BLX-R03: Malformed minhash strings (empty or non-hex)
- FM-BLX-R04: Binary with no traits returns empty matches
- FM-BLX-R05: Trait deduplication and score normalization
"""

import os

import pytest

from src.storage.db import init_db, insert_sample, insert_trait
from src.tools.binlex_runner import (
    compute_minhash_jaccard,
    extract_traits,
    match_traits_against_db,
)


def test_fm_blx_r01_non_existent_binary():
    with pytest.raises(FileNotFoundError):
        extract_traits("/path/to/nonexistent_file_abc.bin")


def test_compute_minhash_jaccard_identical():
    h1 = "1234567890abcdef"
    similarity = compute_minhash_jaccard(h1, h1)
    assert similarity == 1.0


def test_compute_minhash_jaccard_orthogonal():
    h1 = "aaaaaaaaaaaaaaaa"
    h2 = "bbbbbbbbbbbbbbbb"
    similarity = compute_minhash_jaccard(h1, h2)
    assert similarity == 0.0


def test_fm_blx_r03_malformed_minhash():
    assert compute_minhash_jaccard("", "1234") == 0.0
    assert compute_minhash_jaccard(None, "1234") == 0.0
    assert compute_minhash_jaccard("1234", None) == 0.0


def test_fm_blx_r02_missing_db(tmp_path):
    missing_db = str(tmp_path / "missing.db")
    results = match_traits_against_db([], missing_db)
    assert results == []


def test_fm_blx_r04_empty_traits(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    results = match_traits_against_db([], db_path)
    assert results == []


def test_match_traits_against_db_scoring(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    # Insert sample 1 (LummaStealer) with 3 traits
    sha_lumma = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    insert_sample(db_path, sha_lumma, "LummaStealer", "2026-01-01", 5.0)
    insert_trait(db_path, sha_lumma, "block", "55 89 e5 83 ec 10", tlsh_hash="TLSH_A", minhash="minhash_A")
    insert_trait(db_path, sha_lumma, "block", "31 c0 85 c0 74 05", tlsh_hash="TLSH_B", minhash="minhash_B")
    insert_trait(db_path, sha_lumma, "function", "90 90 90 90", tlsh_hash="TLSH_C", minhash="minhash_C")

    # Insert sample 2 (Stealc) with 1 trait
    sha_stealc = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    insert_sample(db_path, sha_stealc, "Stealc", "2026-01-01", 5.2)
    insert_trait(db_path, sha_stealc, "block", "ff 25 00 00 00 00", tlsh_hash="TLSH_D", minhash="minhash_D")

    # Query traits overlapping with LummaStealer
    candidate_traits = [
        {"trait_type": "block", "chromosome_bytes": "55 89 e5 83 ec 10", "tlsh_hash": "TLSH_A", "minhash": "minhash_A"},
        {"trait_type": "block", "chromosome_bytes": "31 c0 85 c0 74 05", "tlsh_hash": "TLSH_B", "minhash": "minhash_B"},
    ]

    matches = match_traits_against_db(candidate_traits, db_path, threshold=0.1)
    assert len(matches) > 0
    top_match = matches[0]
    assert top_match["family"] == "LummaStealer"
    assert top_match["matched_traits_count"] == 2
    assert top_match["similarity_score"] > 0.5


def test_extract_traits_on_system_binary():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    traits = extract_traits(target)
    assert isinstance(traits, list)
    assert len(traits) > 0


def test_fm_blx_r06_rank_mutation_candidates():
    """FM-BLX-R06: Verifies ranking of candidate basic blocks by cyclomatic complexity, entropy, and instructions."""
    from src.tools.binlex_runner import rank_mutation_candidates

    traits = [
        # Candidate A: Small boilerplate (instructions < 3, should be excluded by ranking)
        {"trait_type": "block", "instructions": 2, "cyclomatic_complexity": 1, "trait_entropy": 2.0, "chromosome_bytes": "5d c3"},
        # Candidate B: Ideal decryptor loop (instructions 10, CC 2, good entropy)
        {"trait_type": "block", "instructions": 10, "cyclomatic_complexity": 2, "trait_entropy": 5.2, "chromosome_bytes": "31 c0 80 34 01"},
        # Candidate C: High complexity loop (instructions 20, CC 8, very complex)
        {"trait_type": "block", "instructions": 20, "cyclomatic_complexity": 8, "trait_entropy": 5.0, "chromosome_bytes": "48 89 e5 48 83"},
    ]

    ranked = rank_mutation_candidates(traits, top_n=2)
    assert len(ranked) == 2
    # Candidate B should outrank Candidate C due to optimal decryptor cyclomatic complexity (1-3)
    assert ranked[0]["chromosome_bytes"] == "31 c0 80 34 01"


def test_fm_blx_r07_penalizes_compiler_prologues():
    """FM-BLX-R07: Verifies compiler prologues/epilogues are heavily penalized vs decryptor logic."""
    from src.tools.binlex_runner import rank_mutation_candidates

    traits = [
        # Candidate 1: Standard MSVC prologue (sub rsp, 0x18...)
        {
            "trait_type": "block",
            "instructions": 5,
            "cyclomatic_complexity": 1,
            "trait_entropy": 4.5,
            "chromosome_bytes": "83 ec 18 44 8b 4c 24 28",
        },
        # Candidate 2: Algorithmic decryptor loop (xor, shift)
        {
            "trait_type": "block",
            "instructions": 5,
            "cyclomatic_complexity": 2,
            "trait_entropy": 4.5,
            "chromosome_bytes": "31 c0 d3 e2 80 34 01 48",
        },
    ]

    ranked = rank_mutation_candidates(traits, top_n=2)
    assert ranked[0]["chromosome_bytes"] == "31 c0 d3 e2 80 34 01 48"
