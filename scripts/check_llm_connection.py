#!/usr/bin/env python3
"""Standalone LLM connection check.

Loads config from config/config.example.yaml (or a path you provide),
sends a minimal request to the configured LLM, and reports success or
the specific failure reason.

Usage:
    python scripts/check_llm_connection.py
    python scripts/check_llm_connection.py --config path/to/config.yaml
    python scripts/check_llm_connection.py --model gpt-4o --provider openai
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config.settings import LLMConfig, LLMProviderConfig, SystemConfig


def load_config(config_path: str | None, model_override: str | None, provider_override: str | None) -> LLMProviderConfig:
    if config_path:
        cfg = SystemConfig.from_yaml(config_path)
    else:
        default_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config",
            "config.yaml",
        )
        if os.path.exists(default_path):
            cfg = SystemConfig.from_yaml(default_path)
        else:
            cfg = SystemConfig.default()

    llm_cfg = cfg.llm.planning

    if model_override:
        llm_cfg.model = model_override
    if provider_override:
        llm_cfg.provider = provider_override

    return llm_cfg


async def check_connection(llm_cfg: LLMProviderConfig) -> None:
    print(f"Provider:  {llm_cfg.provider}")
    print(f"Model:     {llm_cfg.model}")
    print(f"API base:  {llm_cfg.api_base or '(default)'}")
    print(f"API key:   {'***' + llm_cfg.api_key[-4:] if llm_cfg.api_key else '(not set)'}")
    print()

    if not llm_cfg.api_key:
        print(f"FAILED: No API key found.")
        print(f"  Set llm.api_key in config.yaml")
        sys.exit(1)

    from src.llm.client import LLMClient

    client = LLMClient(llm_cfg)
    start = time.monotonic()

    try:
        resp = await client.generate(
            [
                {"role": "system", "content": "You are a connection test."},
                {"role": "user", "content": "Respond with exactly one word: OK"},
            ],
            purpose="connection_check",
            temperature=1,
            max_tokens=16,
        )
        response = resp.content
    except Exception as exc:
        elapsed = time.monotonic() - start
        error_msg = str(exc)

        print(f"FAILED ({elapsed:.1f}s)")
        print()

        if "401" in error_msg or "Unauthorized" in error_msg or "invalid_api_key" in error_msg or "AuthenticationError" in error_msg:
            print("  Reason: Invalid API key or unauthorized.")
            print("  Check that your key is correct and has not been revoked.")
        elif "404" in error_msg or "not found" in error_msg.lower():
            print("  Reason: Model or endpoint not found.")
            print(f"  Verify that model '{llm_cfg.model}' exists for provider '{llm_cfg.provider}'.")
            if llm_cfg.api_base:
                print(f"  Also verify api_base: {llm_cfg.api_base}")
        elif "429" in error_msg or "rate" in error_msg.lower():
            print("  Reason: Rate limited.")
            print("  Your API key is valid but you've hit a rate limit. Try again shortly.")
        elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
            print("  Reason: Connection timed out.")
            print("  Check network connectivity and firewall rules.")
        elif "connect" in error_msg.lower() or "resolve" in error_msg.lower():
            print("  Reason: Cannot reach the API endpoint.")
            print("  Check your network connection and DNS resolution.")
        else:
            print(f"  Reason: {error_msg}")

        sys.exit(1)

    elapsed = time.monotonic() - start
    print(f"OK ({elapsed:.1f}s)")
    preview = response.strip()[:80]
    if preview:
        print(f"  Response: {preview}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check LLM connection using project config")
    parser.add_argument("--config", help="Path to config.yaml (default: config/config.yaml)")
    parser.add_argument("--model", help="Override model name")
    parser.add_argument("--provider", help="Override provider name")
    args = parser.parse_args()

    llm_cfg = load_config(args.config, args.model, args.provider)
    asyncio.run(check_connection(llm_cfg))


if __name__ == "__main__":
    main()
