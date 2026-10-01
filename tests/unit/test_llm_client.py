"""
Tests for LLM Client with Primary/Fallback Switching and JSON Extraction (src/agent/llm_client.py).
Failure Modes Covered:
- FM-LLM-01: Missing LLM_API_BASE raises ValueError
- FM-LLM-02: Primary model failure triggers automatic fallback model invocation
- FM-LLM-03: Both models failing raises LLMError
- FM-LLM-04: Robust JSON extraction from markdown fences and conversational wrappers
- FM-LLM-05: Timeout handling raises LLMTimeoutError
"""

import pytest
import requests

from src.agent.llm_client import (
    LLMClient,
    LLMError,
    LLMTimeoutError,
    extract_json_from_llm_response,
)


def test_fm_llm_01_missing_api_base():
    with pytest.raises(ValueError):
        LLMClient(api_base="", primary_model="llama3")


def test_fm_llm_04_extract_json_clean():
    clean_json = '{"attribution": "LummaStealer", "confidence": 0.95}'
    parsed = extract_json_from_llm_response(clean_json)
    assert parsed["attribution"] == "LummaStealer"
    assert parsed["confidence"] == 0.95


def test_fm_llm_04_extract_json_markdown_fences():
    fenced = """Here is the structured analysis of the sample:
```json
{
  "family": "Stealc",
  "verdict": "malicious",
  "threat_score": 9
}
```
Please let me know if you need further details.
"""
    parsed = extract_json_from_llm_response(fenced)
    assert parsed["family"] == "Stealc"
    assert parsed["verdict"] == "malicious"
    assert parsed["threat_score"] == 9


def test_fm_llm_04_extract_json_conversational_embedded():
    conversational = 'Based on the genetic traits, I determined: {"verdict": "packed"} as the result.'
    parsed = extract_json_from_llm_response(conversational)
    assert parsed["verdict"] == "packed"


def test_fm_llm_04_extract_json_invalid():
    with pytest.raises(ValueError):
        extract_json_from_llm_response("No JSON object anywhere in this message!")


def test_fm_llm_02_primary_model_fallback(mocker):
    # Mock requests.post: first call (primary model) fails with 500, second call (fallback) succeeds
    client = LLMClient(
        api_base="https://mock.llm.v1",
        api_key="mock_key",
        primary_model="model_primary",
        fallback_model="model_fallback",
        timeout_seconds=5,
    )

    mock_resp_fail = mocker.MagicMock()
    mock_resp_fail.status_code = 500
    mock_resp_fail.text = "Internal Server Error"
    mock_resp_fail.raise_for_status.side_effect = requests.HTTPError("500 Server Error")

    mock_resp_ok = mocker.MagicMock()
    mock_resp_ok.status_code = 200
    mock_resp_ok.json.return_value = {
        "choices": [{"message": {"content": '{"status": "ok_from_fallback"}'}}]
    }

    mock_post = mocker.patch("requests.post", side_effect=[mock_resp_fail, mock_resp_ok])

    result = client.chat_completion_json(messages=[{"role": "user", "content": "hello"}])
    assert result == {"status": "ok_from_fallback"}
    assert mock_post.call_count == 2
    # Verify fallback model was called in 2nd call
    call_kwargs = mock_post.call_args_list[1][1]
    assert call_kwargs["json"]["model"] == "model_fallback"


def test_fm_llm_03_both_models_fail(mocker):
    client = LLMClient(
        api_base="https://mock.llm.v1",
        api_key="mock_key",
        primary_model="model_primary",
        fallback_model="model_fallback",
        timeout_seconds=5,
    )

    mock_resp_fail = mocker.MagicMock()
    mock_resp_fail.status_code = 502
    mock_resp_fail.raise_for_status.side_effect = requests.HTTPError("502 Bad Gateway")

    mocker.patch("requests.post", side_effect=mock_resp_fail.raise_for_status)

    with pytest.raises(LLMError):
        client.chat_completion_text(messages=[{"role": "user", "content": "hello"}])


def test_fm_llm_05_timeout_handling(mocker):
    client = LLMClient(
        api_base="https://mock.llm.v1",
        api_key="mock_key",
        primary_model="model_primary",
        fallback_model="model_fallback",
        timeout_seconds=2,
    )

    mocker.patch("requests.post", side_effect=requests.Timeout("Connection timed out"))

    with pytest.raises(LLMTimeoutError):
        client.chat_completion_text(messages=[{"role": "user", "content": "hello"}])
