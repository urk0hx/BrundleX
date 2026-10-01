"""
SQLite Database Storage Layer for Genetic Malware Traits.
Implements the schema specified in docs/design.md Section 4.1.
"""

import os
import sqlite3
from typing import Any

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS samples (\n    sha256 TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    first_seen TEXT,
    entropy REAL,
    source TEXT DEFAULT 'malwarebazaar'
);

CREATE TABLE IF NOT EXISTS traits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_sha256 TEXT NOT NULL,
    trait_type TEXT NOT NULL, -- 'function', 'block', 'instruction'
    tlsh_hash TEXT,
    minhash TEXT,
    chromosome_bytes TEXT NOT NULL, -- Wildcarded byte sequence (hex)
    is_library INTEGER DEFAULT 0,   -- 1 = CRT/OpenSSL/Go runtime noise
    FOREIGN KEY(sample_sha256) REFERENCES samples(sha256) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_traits_tlsh ON traits(tlsh_hash);
CREATE INDEX IF NOT EXISTS idx_traits_family ON samples(family);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    """Connect to SQLite database with foreign keys enabled."""
    dir_name = os.path.dirname(db_path)
    if dir_name and not os.path.exists(dir_name):
        raise FileNotFoundError(f"Database directory does not exist: {dir_name}")
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Initializes the database tables and indices."""
    dir_name = os.path.dirname(db_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)


def insert_sample(
    db_path: str,
    sha256: str,
    family: str,
    first_seen: str | None = None,
    entropy: float | None = None,
    source: str = "malwarebazaar",
) -> None:
    """Inserts or updates a sample record."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO samples (sha256, family, first_seen, entropy, source)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                family = excluded.family,
                first_seen = coalesce(excluded.first_seen, samples.first_seen),
                entropy = coalesce(excluded.entropy, samples.entropy),
                source = excluded.source;
            """,
            (sha256, family, first_seen, entropy, source),
        )


def insert_trait(
    db_path: str,
    sample_sha256: str,
    trait_type: str,
    chromosome_bytes: str,
    tlsh_hash: str | None = None,
    minhash: str | None = None,
    is_library: int = 0,
) -> int:
    """Inserts a single trait record and returns its ID."""
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO traits (sample_sha256, trait_type, tlsh_hash, minhash, chromosome_bytes, is_library)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (sample_sha256, trait_type, tlsh_hash, minhash, chromosome_bytes, is_library),
        )
        return cursor.lastrowid


def insert_traits_batch(db_path: str, traits: list[dict[str, Any]]) -> int:
    """
    Inserts a batch of traits in a single atomic transaction.
    Rolls back automatically on failure.
    """
    if not traits:
        return 0

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        for t in traits:
            cursor.execute(
                """
                INSERT INTO traits (sample_sha256, trait_type, tlsh_hash, minhash, chromosome_bytes, is_library)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    t["sample_sha256"],
                    t["trait_type"],
                    t.get("tlsh_hash"),
                    t.get("minhash"),
                    t["chromosome_bytes"],
                    t.get("is_library", 0),
                ),
            )
        return len(traits)


def get_sample(db_path: str, sha256: str) -> dict[str, Any] | None:
    """Retrieves a sample record by sha256."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("SELECT * FROM samples WHERE sha256 = ?;", (sha256,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_traits_by_sample(db_path: str, sha256: str) -> list[dict[str, Any]]:
    """Retrieves all traits belonging to a sample."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("SELECT * FROM traits WHERE sample_sha256 = ?;", (sha256,))
        return [dict(row) for row in cursor.fetchall()]


def get_sample_count(db_path: str) -> int:
    """Returns the total number of indexed samples."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM samples;")
        return cursor.fetchone()[0]


def get_trait_count(db_path: str) -> int:
    """Returns the total number of indexed traits."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM traits;")
        return cursor.fetchone()[0]


def clear_database(db_path: str) -> None:
    """
    Completely purges all samples and traits from the database and vacuums free pages.
    Preserves database schema and index structures.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM traits;")
            conn.execute("DELETE FROM samples;")
        # VACUUM cannot run inside an active transaction block
        conn.isolation_level = None
        conn.execute("VACUUM;")
    finally:
        conn.close()
