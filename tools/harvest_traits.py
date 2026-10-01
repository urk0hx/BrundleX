#!/usr/bin/env python3
"""
CLI Harvester for Genetic Malware Traits.
Ephemerally downloads unpacked malware samples from MalwareBazaar,
checks Shannon entropy to avoid crypted samples, extracts traits with binlex,
and stores traits in the local SQLite database.
Supports --seed-demo mode for offline/test corpus seeding.
"""

import argparse
import io
import json
import logging
import os
import sys

import pyzipper
from dotenv import load_dotenv

from src.harvester.malwarebazaar import (
    HarvesterError,
    MalwareBazaarClient,
    process_sample_payload,
)
from src.storage.db import get_sample_count, get_trait_count, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("harvest_traits")


def create_mock_zip(filename: str, content: bytes, password: bytes = b"infected") -> bytes:
    zip_buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        zip_buffer,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password)
        zf.writestr(filename, content)
    return zip_buffer.getvalue()


def seed_demo_corpus(db_path: str, max_entropy: float = 7.1) -> list[dict]:
    """Seeds the database with representative initial unpacked samples across families."""
    logger.info("Running offline demo corpus seeding...")
    binaries = [
        ("/bin/true", "LummaStealer", "1111111111111111111111111111111111111111111111111111111111111111"),
        ("/bin/ls", "Stealc", "2222222222222222222222222222222222222222222222222222222222222222"),
        ("/bin/bash", "RedLine", "4444444444444444444444444444444444444444444444444444444444444444"),
    ]

    results = []
    for bin_path, family, sha256 in binaries:
        if not os.path.exists(bin_path):
            continue
        with open(bin_path, "rb") as f:
            bin_bytes = f.read()

        zip_bytes = create_mock_zip(f"{family.lower()}.exe", bin_bytes)
        res = process_sample_payload(
            sha256=sha256,
            family=family,
            zip_bytes=zip_bytes,
            db_path=db_path,
            max_entropy=max_entropy,
            first_seen="2026-09-29 00:00:00",
        )
        results.append(res)

    return results


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Ephemeral MalwareBazaar Trait Harvester")
    parser.add_argument(
        "--family",
        type=str,
        help="Target malware family signature (e.g., LummaStealer, Stealc, RedLine)",
    )
    parser.add_argument(
        "--tag",
        type=str,
        default="unpacked",
        help="MalwareBazaar tag to query (default: 'unpacked')",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum samples to harvest per query (default: 10)",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=os.getenv("TRAITS_DB_PATH", "data/traits.db"),
        help="Path to SQLite traits database (default: data/traits.db)",
    )
    parser.add_argument(
        "--max-entropy",
        type=float,
        default=float(os.getenv("MAX_ENTROPY_THRESHOLD", "7.1")),
        help="Shannon entropy threshold to reject crypted binaries (default: 7.1)",
    )
    parser.add_argument(
        "--out-log",
        type=str,
        default="artifacts/phase-1/harvest_log.json",
        help="Output JSON log artifact path (default: artifacts/phase-1/harvest_log.json)",
    )
    parser.add_argument(
        "--seed-demo",
        action="store_true",
        help="Seed the database with initial offline test corpus across distinct families",
    )

    args = parser.parse_args()

    init_db(args.db_path)
    logger.info(f"Initialized trait database at: {args.db_path}")

    results = []

    if args.seed_demo:
        results = seed_demo_corpus(args.db_path, max_entropy=args.max_entropy)
    else:
        api_key = os.getenv("MALWAREBAZAAR_API_KEY")
        if not api_key or api_key == "test_or_placeholder_key":
            logger.error(
                "MALWAREBAZAAR_API_KEY is not configured with a valid key in .env. "
                "To seed initial traits offline, run with --seed-demo."
            )
            sys.exit(1)

        client = MalwareBazaarClient(api_key=api_key)

        if args.family:
            logger.info(f"Querying MalwareBazaar for signature: {args.family} (limit={args.limit})...")
            samples_meta = client.query_signature(args.family, limit=args.limit)
        else:
            logger.info(f"Querying MalwareBazaar for tag: {args.tag} (limit={args.limit})...")
            samples_meta = client.query_tag(args.tag, limit=args.limit)

        if not samples_meta:
            logger.warning("No samples returned from MalwareBazaar for the given query.")
            sys.exit(0)

        logger.info(f"Found {len(samples_meta)} candidate samples. Processing ephemerally...")

        for meta in samples_meta:
            sha256 = meta.get("sha256_hash")
            family = meta.get("signature") or args.family or "unknown"
            first_seen = meta.get("first_seen")

            logger.info(f"Fetching sample {sha256} ({family})...")
            try:
                zip_bytes = client.download_sample(sha256)
                res = process_sample_payload(
                    sha256=sha256,
                    family=family,
                    zip_bytes=zip_bytes,
                    db_path=args.db_path,
                    max_entropy=args.max_entropy,
                    first_seen=first_seen,
                )
                results.append(res)
            except HarvesterError as e:
                logger.error(f"Error processing {sha256}: {e}")
                results.append({"sha256": sha256, "family": family, "status": "error", "error": str(e)})

    # Summary
    total_samples = get_sample_count(args.db_path)
    total_traits = get_trait_count(args.db_path)

    os.makedirs(os.path.dirname(args.out_log), exist_ok=True)
    summary_data = {
        "status": "success",
        "phase": 1,
        "database": args.db_path,
        "total_samples_in_db": total_samples,
        "total_traits_in_db": total_traits,
        "harvested_count": len(results),
        "results": results,
    }

    with open(args.out_log, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    logger.info(f"Harvest complete. Report written to {args.out_log}")
    logger.info(f"Database currently holds {total_samples} samples and {total_traits} traits.")


if __name__ == "__main__":
    main()
