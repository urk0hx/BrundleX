"""
End-to-End Test for Phase 1: Foundation & Data Harvester.
Verifies:
1. Harvester handles password-protected ZIP payloads.
2. Shannon entropy gatekeeper discards packed samples (H > 7.1).
3. Unpacked sample is extracted into ephemeral scratch space /tmp/<sha256>.
4. Binlex extracts traits (basic blocks, functions, chromosome bytes).
5. Traits and sample metadata are indexed into SQLite (data/traits.db).
6. Ephemeral scratch space is guaranteed to be deleted.
7. Verification artifact is written to artifacts/phase-1/harvest_log.json.
"""

import io
import json
import os

import pyzipper

from src.harvester.malwarebazaar import process_sample_payload
from src.storage.db import get_sample_count, get_trait_count, init_db


def create_sample_zip(filename: str, content: bytes, password: bytes = b"infected") -> bytes:
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


def test_phase_1_e2e_pipeline():
    # Setup test paths
    db_path = "data/test_traits_e2e.db"
    artifacts_dir = "artifacts/phase-1"
    os.makedirs("data", exist_ok=True)
    os.makedirs(artifacts_dir, exist_ok=True)

    if os.path.exists(db_path):
        os.remove(db_path)

    init_db(db_path)

    # Read two real binaries to use as legitimate unpacked test payloads
    bin_path_1 = "/bin/true" if os.path.exists("/bin/true") else "/bin/sh"
    bin_path_2 = "/bin/ls" if os.path.exists("/bin/ls") else "/bin/bash"

    with open(bin_path_1, "rb") as f:
        bin1_bytes = f.read()

    with open(bin_path_2, "rb") as f:
        bin2_bytes = f.read()

    # 1. Unpacked sample (Family: LummaStealer mock)
    sha256_unpacked_1 = "1111111111111111111111111111111111111111111111111111111111111111"
    zip_unpacked_1 = create_sample_zip("payload1.bin", bin1_bytes)

    # 2. Unpacked sample (Family: Stealc mock)
    sha256_unpacked_2 = "2222222222222222222222222222222222222222222222222222222222222222"
    zip_unpacked_2 = create_sample_zip("payload2.bin", bin2_bytes)

    # 3. Packed sample with high entropy (Family: CryptorX mock)
    sha256_packed = "3333333333333333333333333333333333333333333333333333333333333333"
    packed_bytes = os.urandom(20000)
    zip_packed = create_sample_zip("packed.exe", packed_bytes)

    log_entries = []

    # Process Sample 1 (Unpacked LummaStealer)
    res1 = process_sample_payload(
        sha256=sha256_unpacked_1,
        family="LummaStealer",
        zip_bytes=zip_unpacked_1,
        db_path=db_path,
        max_entropy=7.1,
    )
    log_entries.append(res1)
    assert res1["status"] == "indexed"
    assert res1["traits_count"] > 0
    assert not os.path.exists(f"/tmp/{sha256_unpacked_1}")

    # Process Sample 2 (Unpacked Stealc)
    res2 = process_sample_payload(
        sha256=sha256_unpacked_2,
        family="Stealc",
        zip_bytes=zip_unpacked_2,
        db_path=db_path,
        max_entropy=7.1,
    )
    log_entries.append(res2)
    assert res2["status"] == "indexed"
    assert res2["traits_count"] > 0
    assert not os.path.exists(f"/tmp/{sha256_unpacked_2}")

    # Process Sample 3 (Packed CryptorX -> Rejected by Entropy Gatekeeper)
    res3 = process_sample_payload(
        sha256=sha256_packed,
        family="CryptorX",
        zip_bytes=zip_packed,
        db_path=db_path,
        max_entropy=7.1,
    )
    log_entries.append(res3)
    assert res3["status"] == "skipped_packed"
    assert res3["entropy"] > 7.1
    assert not os.path.exists(f"/tmp/{sha256_packed}")

    # Verify SQLite state
    total_samples = get_sample_count(db_path)
    total_traits = get_trait_count(db_path)
    assert total_samples == 2
    assert total_traits > 0

    # Write verification proof artifact
    proof_path = os.path.join(artifacts_dir, "harvest_log.json")
    artifact_data = {
        "status": "success",
        "phase": 1,
        "database": db_path,
        "total_samples_indexed": total_samples,
        "total_traits_indexed": total_traits,
        "harvest_log": log_entries,
    }
    with open(proof_path, "w") as f:
        json.dump(artifact_data, f, indent=2)

    assert os.path.exists(proof_path)
    print(f"\n[E2E VERIFICATION COMPLETE] Indexed {total_samples} samples and {total_traits} traits.")
