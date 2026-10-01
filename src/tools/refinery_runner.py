"""
Binary Refinery and Static Deobfuscation Runner.
Provides PE carving, XOR key discovery/scanning, and overlay stripping.
"""

import logging
from typing import Any

import lief
import refinery

logger = logging.getLogger(__name__)

COMMON_PE_STRINGS = [
    b"This program cannot be run in DOS mode",
    b"DOS mode",
    b"kernel32.dll",
    b"GetProcAddress",
    b"LoadLibrary",
    b"http://",
    b"https://",
]


def carve_pe_payloads(data: bytes) -> list[bytes]:
    """
    Carves embedded PE executables from a raw byte stream using refinery
    and header signature heuristics.
    """
    if not data or len(data) < 64:
        return []

    carved_list = []

    # First attempt Refinery's carve_pe unit
    try:
        unit = refinery.carve_pe()
        results = list(unit.process(data))
        for res in results:
            if isinstance(res, (bytes, bytearray)) and len(res) > 0:
                carved_list.append(bytes(res))
    except (ValueError, RuntimeError, KeyError, TypeError, IndexError) as e:
        logger.debug(f"Refinery carve_pe exception: {e}")

    # Fallback to direct PE header scanning (find MZ followed by PE\0\0 within offset)
    if not carved_list:
        offset = 0
        while True:
            idx = data.find(b"MZ", offset)
            if idx == -1 or idx + 64 > len(data):
                break

            e_lfanew = int.from_bytes(data[idx + 60 : idx + 64], byteorder="little")
            if (
                0 < e_lfanew < 4096
                and idx + e_lfanew + 4 <= len(data)
                and data[idx + e_lfanew : idx + e_lfanew + 4] == b"PE\x00\x00"
            ):
                carved_list.append(data[idx:])
                break
            offset = idx + 2

    return carved_list


def scan_xor_keys(data: bytes, max_key_size: int = 1) -> list[dict[str, Any]]:
    """
    Brute-forces XOR keys up to max_key_size bytes, looking for standard indicators
    (DOS stub messages, PE signatures, common imports).
    Returns list of discovered keys and matching decrypted snippets.
    """
    if not data:
        return []

    hits: list[dict[str, Any]] = []

    # Single-byte XOR scan
    if max_key_size >= 1:
        for k in range(1, 256):
            decrypted = bytes([b ^ k for b in data])
            for indicator in COMMON_PE_STRINGS:
                if indicator in decrypted:
                    hits.append({
                        "key": k,
                        "key_size": 1,
                        "matched_indicator": indicator.decode(errors="ignore"),
                        "decrypted": decrypted,
                    })
                    break

    # Also try refinery.autoxor for heuristic entropy / string detection
    try:
        auto_unit = refinery.autoxor()
        auto_res = list(auto_unit.process(data))
        if auto_res and isinstance(auto_res[0], (bytes, bytearray)):
            dec = bytes(auto_res[0])
            if any(ind in dec for ind in COMMON_PE_STRINGS):
                hits.append({
                    "key": "autoxor",
                    "key_size": 1,
                    "matched_indicator": "autoxor_heuristic",
                    "decrypted": dec,
                })
    except (ValueError, RuntimeError, KeyError, TypeError, IndexError) as e:
        logger.debug(f"Refinery autoxor skipped: {e}")

    return hits


def strip_pe_overlay(pe_data: bytes) -> bytes:
    """
    Strips appended overlay data from a PE binary by determining the physical
    end of the declared sections. If the input is not a PE, returns original bytes.
    """
    if not pe_data or len(pe_data) < 64:
        return pe_data

    try:
        parsed = lief.PE.parse(list(pe_data))
        if parsed and parsed.sections:
            end_of_pe = max(s.offset + s.size for s in parsed.sections)
            if 0 < end_of_pe < len(pe_data):
                return pe_data[:end_of_pe]
        return pe_data
    except (ValueError, RuntimeError, KeyError, TypeError, IndexError, lief.lief_errors) as e:
        logger.debug(f"strip_pe_overlay fallback on non-PE: {e}")
        return pe_data


def calculate_pe_hashes(pe_data: bytes) -> dict[str, str]:
    """
    Extracts specialized PE hashes (IMPHASH, AUTHENTIHASH, RICH_HEADER_HASH)
    using lief. If the binary is not a PE or sections are missing, values are empty.
    """
    results = {
        "imphash": "",
        "authentihash": "",
        "rich_header_hash": "",
    }
    if not pe_data or len(pe_data) < 64:
        return results

    try:
        parsed = lief.PE.parse(list(pe_data))
        if not parsed:
            return results

        # IMPHASH
        try:
            ih = lief.PE.get_imphash(parsed)
            if ih:
                results["imphash"] = str(ih).strip().lower()
        except (ValueError, RuntimeError, KeyError, TypeError, IndexError):
            pass

        # AUTHENTIHASH (SHA-256)
        try:
            if parsed.authentihash_sha256:
                results["authentihash"] = bytes(parsed.authentihash_sha256).hex().lower()
        except (ValueError, RuntimeError, KeyError, TypeError, IndexError):
            pass

        # RICH HEADER HASH
        try:
            if parsed.has_rich_header and parsed.rich_header:
                rich_raw = bytes(parsed.rich_header.raw(parsed.rich_header.key))
                if rich_raw:
                    import hashlib
                    results["rich_header_hash"] = hashlib.md5(rich_raw).hexdigest().lower()
        except (ValueError, RuntimeError, KeyError, TypeError, IndexError):
            pass

    except (ValueError, RuntimeError, KeyError, TypeError, IndexError, lief.lief_errors) as e:
        logger.debug(f"calculate_pe_hashes non-PE or malformed: {e}")

    return results
