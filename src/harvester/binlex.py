"""
Binlex Genetic Trait Extraction Runner.
Executes the binlex CLI to extract functions, basic blocks, and chromosome traits.
"""

import hashlib
import json
import logging
import os
import pty
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)


def calculate_file_sha256(file_path: str) -> str:
    """Calculates SHA256 of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def parse_binlex_json_line(
    line: str,
    sample_sha256: str | None = None,
    min_instructions: int = 3,
) -> dict[str, Any] | None:
    """
    Parses a single JSON line emitted by binlex and maps it to our trait schema.
    Filters out trivial compiler boilerplate blocks with fewer than `min_instructions`.
    Captures graph cyclomatic complexity and Shannon entropy metrics for mutation candidate ranking.
    Returns None if the line cannot be parsed or is filtered out as noise.
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    trait_type = data.get("type", "block")
    instructions = data.get("instructions", 0)

    # Filter out trivial 1-2 instruction blocks (e.g. pop rbp; ret) to eliminate compiler boilerplate
    if trait_type == "block" and instructions < min_instructions:
        return None

    chromosome_bytes = data.get("trait") or data.get("bytes") or ""
    tlsh_hash = data.get("bytes_tlsh") or data.get("trait_tlsh")
    minhash = data.get("minhash")
    sha256 = sample_sha256 or data.get("file_sha256") or ""

    # Rich complexity & entropy metrics from binlex
    cyclomatic_complexity = data.get("cyclomatic_complexity", 1)
    trait_entropy = data.get("trait_entropy") or data.get("bytes_entropy", 0.0)
    size = data.get("size", 0)
    offset = data.get("offset", 0)

    return {
        "sample_sha256": sha256,
        "trait_type": trait_type,
        "tlsh_hash": tlsh_hash,
        "minhash": minhash,
        "chromosome_bytes": chromosome_bytes,
        "instructions": instructions,
        "cyclomatic_complexity": cyclomatic_complexity,
        "trait_entropy": float(trait_entropy),
        "size": size,
        "offset": offset,
        "is_library": 0,
    }


def _run_binlex_cli(file_path: str, out_path: str, mode: str, timeout_sec: int) -> None:
    """Executes binlex CLI with a pseudo-terminal (pty) to satisfy ioctl requirements."""
    master, slave = pty.openpty()
    try:
        cmd = ["binlex", "-m", mode, "-i", file_path, "-o", out_path]
        subprocess.run(
            cmd,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            timeout=timeout_sec,
            check=False,
        )
    finally:
        os.close(slave)
        os.close(master)


def extract_traits_from_file(
    file_path: str,
    timeout_sec: int = 60,
    sample_sha256: str | None = None,
    min_instructions: int = 3,
) -> list[dict[str, Any]]:
    """
    Invokes binlex CLI on a binary file and returns parsed trait dictionaries.
    Uses 'auto' mode first; if 0 traits are found (e.g. carved raw shellcode or unmapped memory),
    falls back dynamically to 'raw:x86_64' and 'raw:x86'.
    Filters out trivial basic blocks with < `min_instructions`.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Binary file not found: {file_path}")

    if not sample_sha256:
        sample_sha256 = calculate_file_sha256(file_path)

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as out_file:
        out_path = out_file.name

    try:
        # Pass 1: standard auto mode
        _run_binlex_cli(file_path, out_path, mode="auto", timeout_sec=timeout_sec)

        traits: list[dict[str, Any]] = []
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parsed = parse_binlex_json_line(line, sample_sha256=sample_sha256, min_instructions=min_instructions)
                    if parsed and parsed.get("chromosome_bytes"):
                        traits.append(parsed)

        # Pass 2: Fallback for headerless memory dumps / carved raw shellcode
        # Only fallback if the file appears to be binary machine code (not text)
        is_binary = False
        try:
            with open(file_path, "rb") as bf:
                chunk = bf.read(1024)
                # Check for null bytes or typical non-ASCII machine code
                if b"\x00" in chunk or any(b > 127 for b in chunk):
                    is_binary = True
        except OSError:
            pass

        if not traits and is_binary:
            for fallback_mode in ("raw:x86_64", "raw:x86"):
                try:
                    if os.path.exists(out_path):
                        os.remove(out_path)
                    _run_binlex_cli(file_path, out_path, mode=fallback_mode, timeout_sec=max(timeout_sec // 2, 10))
                    if os.path.exists(out_path):
                        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                parsed = parse_binlex_json_line(
                                    line, sample_sha256=sample_sha256, min_instructions=min_instructions
                                )
                                if parsed and parsed.get("chromosome_bytes"):
                                    traits.append(parsed)
                    if traits:
                        logger.info(f"Binlex fallback mode '{fallback_mode}' successfully extracted {len(traits)} traits.")
                        break
                except (subprocess.SubprocessError, OSError, UnicodeDecodeError) as fallback_err:
                    logger.debug(f"Binlex fallback {fallback_mode} failed: {fallback_err}")

        return traits

    except subprocess.TimeoutExpired:
        logger.warning(f"Binlex timed out on {file_path}")
        return []
    except (subprocess.SubprocessError, OSError, UnicodeDecodeError) as e:
        logger.error(f"Error running binlex on {file_path}: {e}")
        return []
    finally:
        if os.path.exists(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass
