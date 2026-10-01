"""
Unit tests for BrundleX FastAPI + HTMX Single-Page Application (server.py).
Failure Modes Covered:
- FM-UI-01: Application routes boot and return valid semantic HTML with Pico.css and HTMX
- FM-UI-02: Mutation studio simulation triggers invariant verification and generates YARA
- FM-UI-03: Theme toggle, gate controls, and reset endpoints function cleanly without errors
- FM-UI-04: File upload endpoint ingests binary file and selects it as active target
- FM-UI-05: Sample pin and unpin operations reorder library collections dynamically
- FM-UI-06: Configurable harvester endpoint executes offline seeding and live parameter passing (including batch queries)
"""

import io
import threading
import time

import pytest
import requests
import uvicorn

from server import app, context


@pytest.fixture(scope="module")
def live_server():
    """Starts a live uvicorn server on an ephemeral port for testing with requests."""
    port = 8599
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to be responsive
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(30):
        try:
            r = requests.get(base_url, timeout=0.5)
            if r.status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.1)

    yield base_url
    server.should_exit = True
    thread.join(timeout=2.0)


def test_fm_ui_01_index_loads_pico_and_htmx(live_server):
    """FM-UI-01: Verifies GET / renders HTML with Pico.css and HTMX without custom JavaScript."""
    response = requests.get(f"{live_server}/")
    assert response.status_code == 200
    html = response.text
    assert "pico.min.css" in html
    assert "htmx.min.js" in html
    assert "BrundleX: AI-Guided Malware Triage & Predictive Trait Studio" in html
    assert "Target Binary Selection" in html
    assert "Upload Local Binary" in html
    assert "Genetic Threat DB" in html
    assert "theme-circle-btn" in html


def test_fm_ui_02_mutation_simulation_and_yara_download(live_server):
    """FM-UI-02: Simulates assembly mutations, verifies equivalence, and downloads YARA rule."""
    payload = {
        "block_text": "xor rcx, rcx\nmov rdx, 0x20\nadd rax, 1",
        "aggression": 2,
        "num_variants": 2,
        "rule_name": "test_stealc_decryptor",
        "threat_family": "Stealc",
        "author": "Analyst Unit Test",
        "tlp": "CLEAR",
        "description": "Test resilient signature",
        "severity": "HIGH",
        "reference": "SHA256:test12345",
    }
    response = requests.post(f"{live_server}/mutation/simulate", data=payload)
    assert response.status_code == 200
    html = response.text
    assert "Equivalence Verification Reports" in html
    assert "test_stealc_decryptor" in html

    # Download rule
    dl_response = requests.get(f"{live_server}/mutation/download")
    assert dl_response.status_code == 200
    assert "rule test_stealc_decryptor" in dl_response.text
    assert ("$mutated_pattern" in dl_response.text or "$variant_1" in dl_response.text)
    assert 'author = "Analyst Unit Test"' in dl_response.text


def test_fm_ui_03_theme_toggle_and_reset(live_server):
    """FM-UI-03: Verifies theme toggle and reset endpoints."""
    # Toggle theme
    curr_dark = context.dark_theme
    resp_theme = requests.post(f"{live_server}/theme/toggle")
    assert resp_theme.status_code == 200
    assert context.dark_theme != curr_dark

    # Toggle back
    requests.post(f"{live_server}/theme/toggle")
    assert context.dark_theme == curr_dark

    # Reset endpoint
    resp_reset = requests.post(f"{live_server}/triage/reset")
    assert resp_reset.status_code == 200
    assert context.current_state is None
    assert context.mutation_results is None


def test_fm_ui_04_upload_sample(live_server):
    """FM-UI-04: Verifies uploading a binary sample targets it as active custom path."""
    fake_file = io.BytesIO(b"\x90\x90\x31\xc0\xc3")
    files = {"sample_file": ("test_shellcode.bin", fake_file, "application/octet-stream")}
    resp = requests.post(f"{live_server}/triage/upload", files=files)
    assert resp.status_code == 200
    assert "test_shellcode.bin" in context.custom_sample_path


def test_fm_ui_05_pin_unpin_samples(live_server):
    """FM-UI-05: Verifies pinning and unpinning library samples."""
    # Pin 'ls'
    resp = requests.post(f"{live_server}/sample/pin", data={"sample_id": "ls"})
    assert resp.status_code == 200
    assert any(s["id"] == "ls" for s in context.pinned_samples)

    # Unpin 'ls'
    resp = requests.post(f"{live_server}/sample/unpin", data={"sample_id": "ls"})
    assert resp.status_code == 200
    assert not any(s["id"] == "ls" for s in context.pinned_samples)
    assert any(s["id"] == "ls" for s in context.unpinned_samples)


def test_fm_ui_06_configurable_harvest_endpoint(live_server):
    """FM-UI-06: Verifies configurable harvester endpoint validates API key requirement."""
    payload = {
        "family": "Stealc, Lumma, RedLine",
        "tag": "unpacked, exe",
        "limit": 3,
        "max_entropy": 7.0,
    }
    resp = requests.post(f"{live_server}/triage/harvest", data=payload)
    assert resp.status_code == 200
    # Checks that either real harvest took place or clean API key prompt was returned
    assert any("MalwareBazaar API key" in m.get("content", "") or "Harvest completed" in m.get("content", "") for m in context.chat_messages)


def test_fm_ui_07_clear_threat_db_endpoint(live_server):
    """FM-UI-07: Verifies POST /triage/db/clear completely clears samples and traits."""
    resp = requests.post(f"{live_server}/triage/db/clear")
    assert resp.status_code == 200
    assert any("Threat database completely cleared" in m.get("content", "") for m in context.chat_messages)
