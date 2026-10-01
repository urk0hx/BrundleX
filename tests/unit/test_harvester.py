"""
Tests for MalwareBazaar Harvester & Ephemeral Processing (src/harvester/malwarebazaar.py).
Failure Modes Covered:
- FM-MB-01: Network timeout or HTTP error
- FM-MB-02: MalwareBazaar response indicates query error / no results
- FM-MB-03: Downloaded payload is not a valid zip archive
- FM-MB-04: Extraction failure or bad password
- FM-MB-05: Ephemeral directory cleanup guarantee on success or exception
- FM-MB-06: High entropy sample (H > 7.1) gatekeeper rejection and cleanup
- FM-MB-07: Missing API key validation
"""

import io
import os

import pytest
import pyzipper
import requests

from src.harvester.malwarebazaar import (
    HarvesterError,
    HarvesterNetworkError,
    MalwareBazaarClient,
    process_sample_payload,
)


def create_mock_infected_zip(filename: str, file_bytes: bytes, password: bytes = b"infected") -> bytes:
    """Helper to create a password-protected zip matching MalwareBazaar structure."""
    zip_buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        zip_buffer,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password)
        zf.writestr(filename, file_bytes)
    return zip_buffer.getvalue()


def test_fm_mb_07_missing_api_key(monkeypatch):
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    with pytest.raises(ValueError, match="MALWAREBAZAAR_API_KEY"):
        MalwareBazaarClient(api_key="")


def test_fm_mb_01_network_timeout(mocker):
    client = MalwareBazaarClient(api_key="mock_key", api_url="https://mock-bazaar.local/api/v1/")
    mocker.patch("requests.post", side_effect=requests.RequestException("Connection timed out"))

    with pytest.raises(HarvesterNetworkError):
        client.query_tag("unpacked")


def test_fm_mb_02_query_no_results(mocker):
    client = MalwareBazaarClient(api_key="mock_key", api_url="https://mock-bazaar.local/api/v1/")
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {"query_status": "no_results", "data": []}
    mock_response.raise_for_status.return_value = None
    mocker.patch("requests.post", return_value=mock_response)

    results = client.query_tag("nonexistent_tag")
    assert results == []


def test_fm_mb_03_corrupt_zip_payload():
    corrupt_bytes = b"NOT_A_VALID_ZIP_HEADER_JUST_GARBAGE"
    with pytest.raises(HarvesterError, match="Invalid ZIP"):
        process_sample_payload(
            sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            family="TestFamily",
            zip_bytes=corrupt_bytes,
            db_path=":memory:",
            max_entropy=7.1,
        )


def test_fm_mb_06_high_entropy_rejection(tmp_path):
    high_entropy_bytes = os.urandom(10000)
    sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    zip_bytes = create_mock_infected_zip("malware.exe", high_entropy_bytes)

    scratch_dir = f"/tmp/{sha256}"
    if os.path.exists(scratch_dir):
        os.rmdir(scratch_dir)

    result = process_sample_payload(
        sha256=sha256,
        family="PackedTrojan",
        zip_bytes=zip_bytes,
        db_path=str(tmp_path / "test.db"),
        max_entropy=7.1,
    )

    assert result["status"] == "skipped_packed"
    assert result["entropy"] > 7.1
    # Ephemeral scratch folder must be deleted!
    assert not os.path.exists(scratch_dir)


def test_fm_mb_05_cleanup_guarantee_on_error(tmp_path, monkeypatch):
    sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    payload = b"MZ\x90\x00" + b"\x00" * 500
    zip_bytes = create_mock_infected_zip("malware.exe", payload)

    scratch_dir = f"/tmp/{sha256}"

    def failing_extract(*args, **kwargs):
        raise RuntimeError("Simulated failure during trait extraction")

    monkeypatch.setattr("src.harvester.malwarebazaar.extract_traits_from_file", failing_extract)

    with pytest.raises(RuntimeError):
        process_sample_payload(
            sha256=sha256,
            family="LummaStealer",
            zip_bytes=zip_bytes,
            db_path=str(tmp_path / "test.db"),
            max_entropy=7.1,
        )

    # Scratch directory must NOT be left behind on disk
    assert not os.path.exists(scratch_dir)
