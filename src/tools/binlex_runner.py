"""
Binlex Genetic Trait Extraction and Database Matching Runner.
Wraps binlex CLI execution and provides Jaccard MinHash and TLSH similarity
matching against the SQLite traits database.
"""

import os
import sqlite3
from collections import defaultdict
from typing import Any

from src.harvester.binlex import extract_traits_from_file


def extract_traits(file_path: str, timeout_sec: int = 60) -> list[dict[str, Any]]:
    """
    Extracts basic block and function traits from a binary file.
    Raises FileNotFoundError if file does not exist.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Binary file not found: {file_path}")

    return extract_traits_from_file(file_path, timeout_sec=timeout_sec)


def compute_minhash_jaccard(minhash_a: str | None, minhash_b: str | None) -> float:
    """
    Computes Jaccard similarity between two MinHash strings.
    Returns float in range [0.0, 1.0].
    """
    if not minhash_a or not minhash_b:
        return 0.0

    if minhash_a == minhash_b:
        return 1.0

    # Tokenize into n-grams or sub-components (space-separated or chunked hex)
    tokens_a = set(minhash_a.split()) if " " in minhash_a else {minhash_a[i : i + 4] for i in range(0, len(minhash_a), 4)}
    tokens_b = set(minhash_b.split()) if " " in minhash_b else {minhash_b[i : i + 4] for i in range(0, len(minhash_b), 4)}

    if not tokens_a or not tokens_b:
        return 0.0

    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return intersection / union if union > 0 else 0.0


def match_traits_against_db(
    sample_traits: list[dict[str, Any]],
    db_path: str,
    threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """
    Matches a collection of extracted traits against the database.
    Aggregates matching trait counts and calculates similarity scores by family and sample.
    Returns list of matches sorted by similarity score descending.
    """
    if not sample_traits or not os.path.exists(db_path):
        return []

    # Collect query traits by tlsh and chromosome_bytes
    tlsh_set = {t["tlsh_hash"] for t in sample_traits if t.get("tlsh_hash")}
    chromosome_set = {t["chromosome_bytes"] for t in sample_traits if t.get("chromosome_bytes")}

    if not tlsh_set and not chromosome_set:
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Query matching traits in batches
    matches_by_sample: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "family": "", "total_db_traits": 0})

    try:
        # Get count of total traits per sample in DB for normalization
        cursor.execute("SELECT sample_sha256, COUNT(*) as cnt FROM traits GROUP BY sample_sha256;")
        db_trait_counts = {row["sample_sha256"]: row["cnt"] for row in cursor.fetchall()}

        # Match by TLSH
        if tlsh_set:
            placeholders = ",".join("?" for _ in tlsh_set)
            cursor.execute(
                f"""
                SELECT t.sample_sha256, s.family, COUNT(t.id) as match_cnt
                FROM traits t
                JOIN samples s ON t.sample_sha256 = s.sha256
                WHERE t.tlsh_hash IN ({placeholders})
                GROUP BY t.sample_sha256, s.family;
                """,
                list(tlsh_set),
            )
            for row in cursor.fetchall():
                sha = row["sample_sha256"]
                matches_by_sample[sha]["count"] += row["match_cnt"]
                matches_by_sample[sha]["family"] = row["family"]
                matches_by_sample[sha]["total_db_traits"] = db_trait_counts.get(sha, 1)

        # Match by chromosome bytes if TLSH alone yielded few
        if chromosome_set:
            chrom_sample = list(chromosome_set)[:200]  # Cap for query performance
            placeholders = ",".join("?" for _ in chrom_sample)
            cursor.execute(
                f"""
                SELECT t.sample_sha256, s.family, COUNT(t.id) as match_cnt
                FROM traits t
                JOIN samples s ON t.sample_sha256 = s.sha256
                WHERE t.chromosome_bytes IN ({placeholders})
                GROUP BY t.sample_sha256, s.family;
                """,
                chrom_sample,
            )
            for row in cursor.fetchall():
                sha = row["sample_sha256"]
                matches_by_sample[sha]["count"] = max(matches_by_sample[sha]["count"], row["match_cnt"])
                matches_by_sample[sha]["family"] = row["family"]
                matches_by_sample[sha]["total_db_traits"] = db_trait_counts.get(sha, 1)

    finally:
        conn.close()

    total_query_traits = len(sample_traits)
    results = []

    for sha, data in matches_by_sample.items():
        matched_cnt = data["count"]
        db_total = max(data["total_db_traits"], 1)
        # Jaccard-like trait overlap: matched / (query + db - matched)
        denominator = total_query_traits + db_total - matched_cnt
        score = matched_cnt / denominator if denominator > 0 else 0.0

        if score >= threshold or matched_cnt >= 2:
            results.append({
                "sample_sha256": sha,
                "family": data["family"],
                "matched_traits_count": matched_cnt,
                "similarity_score": round(score, 4),
            })

    results.sort(key=lambda x: (x["similarity_score"], x["matched_traits_count"]), reverse=True)
    return results


def rank_mutation_candidates(traits: list[dict[str, Any]], top_n: int = 5) -> list[dict[str, Any]]:
    """
    Ranks basic block traits as candidates for predictive mutation simulation.
    Prioritizes blocks with moderate cyclomatic complexity (1-3, ideal for decryptor loops),
    substantial instruction count (>= 3 instructions), and non-zero entropy.
    """
    candidates = [
        t for t in traits
        if t.get("trait_type") == "block" and t.get("instructions", 0) >= 3 and t.get("chromosome_bytes")
    ]

    def score_candidate(c: dict[str, Any]) -> float:
        # Decryption blocks typically have cyclomatic complexity 1 to 3
        cc = c.get("cyclomatic_complexity", 1)
        cc_weight = 3.0 if 1 <= cc <= 3 else (1.0 if cc <= 5 else 0.2)
        # Moderate to high entropy (4.0 - 6.5) suggests algorithmic processing rather than ASCII or padding
        entropy = c.get("trait_entropy", 0.0)
        ent_weight = min(entropy / 5.0, 1.5)
        # Sufficient instruction length (5 to 25 instructions is typical for compact decryption/derivation stubs)
        instr = min(c.get("instructions", 0), 30)
        return cc_weight * ent_weight * instr

    candidates.sort(key=score_candidate, reverse=True)
    return candidates[:top_n]
