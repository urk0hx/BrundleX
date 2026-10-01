"""
OpenAI-Compatible LLM Client with Primary/Fallback Model Switching and JSON Extraction.
Targeted for local or remote endpoints (Ollama, LM Studio, vLLM, OpenAI, etc.).
"""

import json
import logging
import os
import re
from typing import Any

import requests

logger = logging.getLogger(__name__)


class LLMError(Exception):
    """Generic error raised when communicating with LLM endpoint."""


class LLMTimeoutError(LLMError):
    """Raised when LLM request times out."""


def extract_json_from_llm_response(text: str) -> dict[str, Any]:
    """
    Extracts and parses a JSON object from LLM response text,
    handling markdown code fences (```json ... ```) and embedded objects.
    """
    if not text or not text.strip():
        raise ValueError("Cannot extract JSON from empty LLM response.")

    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.DOTALL).strip()
    target_text = cleaned or text

    # 1. Look for ```json ... ``` or ``` ... ``` code blocks
    fence_pattern = r"```(?:json)?\s*([\s\S]*?)\s*```"
    fence_matches = re.findall(fence_pattern, target_text, re.IGNORECASE)
    for block in fence_matches:
        try:
            return json.loads(block.strip())
        except json.JSONDecodeError:
            continue

    # 2. Look for outermost balanced { ... }
    first_brace = target_text.find("{")
    last_brace = target_text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = target_text[first_brace : last_brace + 1].strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # 3. Direct parse attempt
    try:
        return json.loads(target_text.strip())
    except json.JSONDecodeError as err:
        raise ValueError(f"Could not extract valid JSON from LLM output: {err}\nOutput was: {target_text[:200]}") from err


class LLMClient:
    """OpenAI-compatible client with primary and fallback model resilience."""

    def __init__(
        self,
        api_base: str | None = None,
        api_key: str | None = None,
        primary_model: str | None = None,
        fallback_model: str | None = None,
        timeout_seconds: int | None = None,
    ):
        if api_base is not None:
            self.api_base = api_base.rstrip("/")
        else:
            self.api_base = os.getenv("LLM_API_BASE", "").rstrip("/")

        if not self.api_base:
            raise ValueError(
                "LLM_API_BASE is required and must not be empty. "
                "Configure it in your .env file or pass it to LLMClient."
            )

        self.api_key = api_key if api_key is not None else os.getenv("LLM_API_KEY", "")
        self.primary_model = primary_model if primary_model is not None else os.getenv("LLM_MODEL", "llama3:8b")
        self.fallback_model = fallback_model if fallback_model is not None else os.getenv("LLM_FALLBACK_MODEL", "")

        if timeout_seconds is not None:
            self.timeout_seconds = timeout_seconds
        else:
            self.timeout_seconds = int(os.getenv("LLM_TIMEOUT_SECONDS", "60"))

    def _call_model(
        self,
        model_name: str,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> str:
        """Executes a single chat completion HTTP request."""
        url = f"{self.api_base}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": model_name,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise LLMError(f"LLM endpoint returned no choices in response: {data}")
            return choices[0].get("message", {}).get("content", "")
        except requests.Timeout as timeout_err:
            raise LLMTimeoutError(f"Request to LLM model '{model_name}' timed out: {timeout_err}") from timeout_err
        except requests.RequestException as req_err:
            raise LLMError(f"Request to LLM model '{model_name}' failed: {req_err}") from req_err

    def chat_completion_text(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> str:
        """
        Attempts inference using primary_model. If it fails and fallback_model is defined,
        retries inference using fallback_model.
        """
        try:
            return self._call_model(
                model_name=self.primary_model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        except LLMTimeoutError:
            # Re-raise timeout directly or try fallback
            if self.fallback_model and self.fallback_model != self.primary_model:
                logger.warning(
                    f"Primary model '{self.primary_model}' timed out. Attempting fallback '{self.fallback_model}'..."
                )
                return self._call_model(
                    model_name=self.fallback_model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            raise
        except LLMError as primary_err:
            if self.fallback_model and self.fallback_model != self.primary_model:
                logger.warning(
                    f"Primary model '{self.primary_model}' failed ({primary_err}). "
                    f"Attempting fallback model '{self.fallback_model}'..."
                )
                try:
                    return self._call_model(
                        model_name=self.fallback_model,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )
                except Exception as fallback_err:
                    raise LLMError(
                        f"Both primary ('{self.primary_model}') and fallback ('{self.fallback_model}') failed. "
                        f"Primary: {primary_err} | Fallback: {fallback_err}"
                    ) from fallback_err
            raise

    def chat_completion_json(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        """Requests chat completion and parses response into a validated JSON dictionary."""
        raw_text = self.chat_completion_text(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return extract_json_from_llm_response(raw_text)
