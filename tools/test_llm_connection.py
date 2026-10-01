#!/usr/bin/env python3
"""
Test and diagnose connection to OpenAI-compatible LLM endpoint.
Lists available models and verifies chat completion for both primary and fallback models.
"""

import json
import os
import sys

import requests
from dotenv import load_dotenv


def main():
    load_dotenv()

    api_base = os.getenv("LLM_API_BASE", "").rstrip("/")
    api_key = os.getenv("LLM_API_KEY", "")
    main_model = os.getenv("LLM_MODEL", "")
    fallback_model = os.getenv("LLM_FALLBACK_MODEL", "")
    timeout = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))

    print("==================================================")
    print("      BrundleX LLM Endpoint Connection Test       ")
    print("==================================================")

    if not api_base:
        print("[ERROR] LLM_API_BASE is not set in your .env file.")
        print("Please configure LLM_API_BASE in .env (see .env.example for guidance).")
        sys.exit(1)

    print(f"Endpoint URL    : {api_base}")
    print(f"Primary Model   : {main_model or '(Not specified)'}")
    print(f"Fallback Model  : {fallback_model or '(Not specified)'}")
    print(f"Timeout (sec)   : {timeout}")
    print("--------------------------------------------------")

    headers = {
        "Content-Type": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # 1. Test /models endpoint
    models_url = f"{api_base}/models"
    print(f"\n[1/3] Querying available models from: {models_url} ...")
    try:
        resp = requests.get(models_url, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        print(f"[FAIL] Could not connect to LLM endpoint: {e}")
        print("\nTroubleshooting tips:")
        print("1. If using Ollama/LM Studio on the host machine from inside Podman:")
        print("   - Ensure the server is running and listening on 0.0.0.0 (or localhost with --network host).")
        print("   - Try setting LLM_API_BASE=http://localhost:<port>/v1 with 'make test-llm'.")
        print("2. Verify that your firewall or container permissions allow localhost access.")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"[FAIL] HTTP {resp.status_code} received from {models_url}")
        print(f"Response body: {resp.text[:500]}")
        sys.exit(1)

    try:
        data = resp.json()
    except json.JSONDecodeError:
        print(f"[FAIL] Response from {models_url} was not valid JSON.")
        print(f"Raw response: {resp.text[:500]}")
        sys.exit(1)

    raw_models = data.get("data", [])
    model_ids = [m.get("id") for m in raw_models if isinstance(m, dict) and "id" in m]

    print(f"[SUCCESS] Connected! Found {len(model_ids)} available models:\n")
    for idx, mid in enumerate(model_ids, 1):
        tags = []
        if mid == main_model:
            tags.append("[PRIMARY]")
        if mid == fallback_model:
            tags.append("[FALLBACK]")
        tag_str = f" {' '.join(tags)}" if tags else ""
        print(f"  {idx:2d}. {mid}{tag_str}")

    # Check model presence
    if main_model:
        if model_ids and main_model not in model_ids:
            print(f"\n[WARNING] Primary model '{main_model}' was not found in the models list.")
        else:
            print(f"\n[INFO] Primary model '{main_model}' is available.")

    # 2. Test chat completion with Primary Model
    chat_url = f"{api_base}/chat/completions"
    test_models = [m for m in [main_model, fallback_model] if m]
    if not test_models and model_ids:
        test_models = [model_ids[0]]

    for role_name, model_candidate in [("Primary", main_model), ("Fallback", fallback_model)]:
        if not model_candidate:
            continue

        print(f"\n[2/3] Testing inference with {role_name} model: '{model_candidate}' ...")
        payload = {
            "model": model_candidate,
            "messages": [
                {"role": "system", "content": "You are a test agent."},
                {"role": "user", "content": "Respond strictly with the single word 'Operational'."},
            ],
            "max_tokens": 16,
            "temperature": 0.0,
        }

        try:
            chat_resp = requests.post(chat_url, headers=headers, json=payload, timeout=timeout)
            if chat_resp.status_code == 200:
                result_json = chat_resp.json()
                content = (
                    result_json.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                    .strip()
                )
                print(f"[SUCCESS] {role_name} model responded: '{content}'")
            else:
                print(f"[WARN] {role_name} model returned HTTP {chat_resp.status_code}: {chat_resp.text[:200]}")
        except requests.RequestException as req_err:
            print(f"[WARN] Connection error during {role_name} model test: {req_err}")

    print("\n--------------------------------------------------")
    print("[COMPLETED] LLM endpoint test finished.")
    print("==================================================")


if __name__ == "__main__":
    main()
