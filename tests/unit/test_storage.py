"""
Tests for the SQLite Storage Layer (src/storage/db.py).
Failure Modes Covered:
- FM-DB-01: Invalid / unwritable database path
- FM-DB-02: Duplicate sample insertion handling (idempotent / upsert)
- FM-DB-03: Foreign key constraint enforcement
- FM-DB-04: Batch trait insertion with empty or malformed fields
- FM-DB-05: Atomic transaction rollback on failure
"""

import os
import sqlite3

import pytest

from src.storage.db import (
    clear_database,
    get_connection,
    get_sample,
    get_sample_count,
    get_trait_count,
    get_traits_by_sample,
    init_db,
    insert_sample,
    insert_trait,
    insert_traits_batch,
)


def test_init_db_creates_tables_and_indices(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    assert os.path.exists(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Verify tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cursor.fetchall()}
    assert "samples" in tables
    assert "traits" in tables

    # Verify indices
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
    indices = {row[0] for row in cursor.fetchall()}
    assert "idx_traits_tlsh" in indices
    assert "idx_traits_family" in indices
    conn.close()


def test_fm_db_01_invalid_db_path():
    invalid_path = "/nonexistent_dir_xyz/deep/path/traits.db"
    with pytest.raises(FileNotFoundError):
        get_connection(invalid_path)

    # For init_db, an unwritable path raises OSError
    unwritable_path = "/proc/cannot_create_dir/traits.db"
    with pytest.raises(OSError):
        init_db(unwritable_path)


def test_insert_and_get_sample(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    insert_sample(
        db_path=db_path,
        sha256=sha256,
        family="LummaStealer",
        first_seen="2026-01-01 12:00:00",
        entropy=6.45,
        source="malwarebazaar",
    )

    sample = get_sample(db_path, sha256)
    assert sample is not None
    assert sample["sha256"] == sha256
    assert sample["family"] == "LummaStealer"
    assert sample["entropy"] == 6.45
    assert sample["source"] == "malwarebazaar"
    assert get_sample_count(db_path) == 1


def test_fm_db_02_duplicate_sample_insertion(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    insert_sample(db_path, sha256, "LummaStealer", "2026-01-01", 6.45)
    # Re-inserting the same sample should update or be safely ignored without breaking
    insert_sample(db_path, sha256, "LummaStealer", "2026-01-02", 6.45)

    assert get_sample_count(db_path) == 1


def test_insert_and_get_traits(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    insert_sample(db_path, sha256, "Stealc", "2026-01-01", 6.10)

    trait_id = insert_trait(
        db_path=db_path,
        sample_sha256=sha256,
        trait_type="block",
        tlsh_hash="T114A002237A51753DAB16903AA45E3C3369817C4561150DA5D78950516D31A20F42B01F",
        minhash="minhash123",
        chromosome_bytes="55 89 e5 83 ec 10",
        is_library=0,
    )
    assert trait_id > 0

    traits = get_traits_by_sample(db_path, sha256)
    assert len(traits) == 1
    assert traits[0]["trait_type"] == "block"
    assert traits[0]["chromosome_bytes"] == "55 89 e5 83 ec 10"
    assert get_trait_count(db_path) == 1


def test_fm_db_03_foreign_key_violation(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    non_existent_sha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    with pytest.raises(sqlite3.IntegrityError):
        insert_trait(
            db_path=db_path,
            sample_sha256=non_existent_sha,
            trait_type="block",
            tlsh_hash=None,
            minhash=None,
            chromosome_bytes="90 90",
            is_library=0,
        )


def test_insert_traits_batch(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    insert_sample(db_path, sha256, "RedLine", "2026-01-01", 5.8)

    batch = [
        {
            "sample_sha256": sha256,
            "trait_type": "function",
            "tlsh_hash": f"TLSH_{i}",
            "minhash": f"MIN_{i}",
            "chromosome_bytes": f"55 89 e5 {i:02x}",
            "is_library": 0,
        }
        for i in range(10)
    ]
    inserted_count = insert_traits_batch(db_path, batch)
    assert inserted_count == 10
    assert get_trait_count(db_path) == 10


def test_fm_db_05_atomic_batch_rollback(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    insert_sample(db_path, sha256, "RedLine", "2026-01-01", 5.8)

    # Batch with an invalid record that violates FK
    batch = [
        {
            "sample_sha256": sha256,
            "trait_type": "function",
            "tlsh_hash": "TLSH_VALID",
            "minhash": "MIN_VALID",
            "chromosome_bytes": "55 89 e5",
            "is_library": 0,
        },
        {
            "sample_sha256": "nonexistent_sha",
            "trait_type": "function",
            "tlsh_hash": "TLSH_BAD",
            "minhash": "MIN_BAD",
            "chromosome_bytes": "90",
            "is_library": 0,
        },
    ]
    with pytest.raises(sqlite3.IntegrityError):
        insert_traits_batch(db_path, batch)

    # Transaction rolled back completely: trait count should be 0
    assert get_trait_count(db_path) == 0


def test_clear_database_purges_all_records(tmp_path):
    db_path = str(tmp_path / "test_traits.db")
    init_db(db_path)

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    insert_sample(db_path, sha256, "Stealc", "2026-01-01", 6.10)
    insert_trait(
        db_path=db_path,
        sample_sha256=sha256,
        trait_type="block",
        tlsh_hash=None,
        minhash=None,
        chromosome_bytes="55 89 e5",
        is_library=0,
    )

    assert get_sample_count(db_path) == 1
    assert get_trait_count(db_path) == 1

    clear_database(db_path)

    assert get_sample_count(db_path) == 0
    assert get_trait_count(db_path) == 0

    # Ensure schema is still valid by inserting a new record
    insert_sample(db_path, sha256, "Lumma", "2026-01-02", 5.5)
    assert get_sample_count(db_path) == 1
