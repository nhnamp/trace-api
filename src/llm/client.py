from __future__ import annotations

import asyncio
import json
import re
import time

import structlog
from json_repair import repair_json
from pydantic import BaseModel

from src.config.settings import LLMProviderConfig
from src.llm.logger import LLMCallRecord, LLMLogger
from src.llm.token_budget import count_tokens

logger = structlog.get_logger(__name__)


def extract_json(text: str) -> str:
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    else:
        text = text.strip()
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = text.find(start_char)
            end = text.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                text = text[start : end + 1]
                break

    text = re.sub(r"(?<!:)//[^\n]*", "", text)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


def loads_json(text: str) -> object:
    cleaned = extract_json(text)
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        repaired = repair_json(cleaned, return_objects=True)
        if repaired == "" or repaired is None or isinstance(repaired, (str, int, float, bool)):
            raise ValueError("json_repair could not recover a JSON object/array") from None
        return repaired


class LLMError(Exception):
    pass


class LLMResponse:
    def __init__(
        self,
        content: str,
        usage: dict,
        model: str,
        latency_ms: int,
        raw_response: object = None,
    ):
        self.content = content
        self.usage = usage
        self.model = model
        self.latency_ms = latency_ms
        self.raw_response = raw_response


class LLMClient:
    def __init__(self, config: LLMProviderConfig, llm_logger: LLMLogger | None = None):
        self.config = config
        self.llm_logger = llm_logger

    def _build_model_string(self) -> str:
        provider = self.config.provider.lower()
        model = self.config.model
        if provider == "openai" or model.startswith(("gpt-", "o1-", "o3-")):
            return model
        if provider in ("ollama", "huggingface", "bedrock", "vertex_ai"):
            return f"{provider}/{model}"
        return model

    @staticmethod
    async def _consume_stream(litellm, kwargs: dict) -> tuple[str, dict, str | None]:
        parts: list[str] = []
        usage: dict = {}
        finish_reason: str | None = None

        stream = await litellm.acompletion(**kwargs)
        async for chunk in stream:
            choices = getattr(chunk, "choices", None) or []
            if choices:
                fr = getattr(choices[0], "finish_reason", None)
                if fr:
                    finish_reason = fr
                delta = getattr(choices[0], "delta", None)
                piece = getattr(delta, "content", None) if delta is not None else None
                if piece:
                    parts.append(piece)

            chunk_usage = getattr(chunk, "usage", None)
            if chunk_usage:
                usage = {
                    "prompt_tokens": getattr(chunk_usage, "prompt_tokens", None),
                    "completion_tokens": getattr(chunk_usage, "completion_tokens", None),
                    "total_tokens": getattr(chunk_usage, "total_tokens", None),
                }

        if finish_reason == "error":
            raise LLMError("provider returned finish_reason=error (streaming)")
        return "".join(parts), usage, finish_reason

    @staticmethod
    async def _complete(litellm, kwargs: dict) -> tuple[str, dict, str | None]:
        raw = await litellm.acompletion(**kwargs)
        choice = raw.choices[0]
        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason == "error":
            raise LLMError("provider returned finish_reason=error")
        content = choice.message.content or ""
        usage: dict = {}
        raw_usage = getattr(raw, "usage", None)
        if raw_usage:
            usage = {
                "prompt_tokens": getattr(raw_usage, "prompt_tokens", None),
                "completion_tokens": getattr(raw_usage, "completion_tokens", None),
                "total_tokens": getattr(raw_usage, "total_tokens", None),
            }
        return content, usage, finish_reason

    async def generate(
        self,
        messages: list[dict],
        *,
        purpose: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        import litellm

        model_str = self._build_model_string()
        kwargs: dict = {
            "model": model_str,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
            "drop_params": True,
        }
        use_stream = self.config.stream if self.config.stream is not None else True
        if use_stream:
            kwargs["stream"] = True
            kwargs["stream_options"] = {"include_usage": True}
        if self.config.extra_headers:
            kwargs["extra_headers"] = self.config.extra_headers
        if self.config.extra_body:
            kwargs["extra_body"] = self.config.extra_body
        if response_format is not None:
            kwargs["response_format"] = response_format
        if self.config.api_key:
            kwargs["api_key"] = self.config.api_key
        if self.config.api_base:
            kwargs["api_base"] = self.config.api_base

        start = time.monotonic()
        attempts = 1 + max(0, self.config.num_retries or 0)
        last_exc: Exception | None = None
        content, usage = "", {}
        agg_prompt = 0
        agg_completion = 0
        api_calls = 0

        requested_max = max_tokens or self.config.max_tokens
        effective_max = requested_max
        context_window = self.config.context_window
        if context_window:
            input_tokens = sum(count_tokens(m.get("content", "") or "") for m in messages)
            max_completion_ceiling = max(requested_max, context_window - input_tokens - 512)
        else:
            max_completion_ceiling = requested_max

        for attempt in range(attempts):
            kwargs["max_tokens"] = effective_max
            api_calls += 1
            transient = False
            try:
                if use_stream:
                    content, usage, finish_reason = await self._consume_stream(litellm, kwargs)
                else:
                    content, usage, finish_reason = await self._complete(litellm, kwargs)
                if usage:
                    agg_prompt += usage.get("prompt_tokens") or 0
                    agg_completion += usage.get("completion_tokens") or 0
                completion_tokens = usage.get("completion_tokens") if usage else None
                truncated = finish_reason == "length"
                if content.strip() and completion_tokens != 0 and not truncated:
                    last_exc = None
                    break
                detail = (
                    "truncated (finish_reason=length)"
                    if truncated
                    else f"empty (completion_tokens={completion_tokens})"
                )
                last_exc = LLMError(f"provider returned a failed/incomplete response: {detail}")
                if effective_max < max_completion_ceiling:
                    effective_max = min(max_completion_ceiling, int(effective_max * 1.5))
            except Exception as exc:
                last_exc = exc
                transient = True
            logger.warning(
                "llm_call_retry",
                model=model_str,
                purpose=purpose,
                attempt=attempt + 1,
                attempts=attempts,
                max_tokens=effective_max,
                error=str(last_exc)[:200],
            )
            if attempt < attempts - 1 and transient:
                await asyncio.sleep(min(2 ** attempt, 8))
        if last_exc is not None:
            logger.error(
                "llm_call_failed",
                model=model_str,
                purpose=purpose,
                error=str(last_exc),
            )
            raise LLMError(f"LLM call failed ({model_str}): {last_exc}") from last_exc
        latency_ms = int((time.monotonic() - start) * 1000)

        usage = {
            "prompt_tokens": agg_prompt or (usage.get("prompt_tokens") if usage else None),
            "completion_tokens": agg_completion or (usage.get("completion_tokens") if usage else None),
            "total_tokens": (agg_prompt + agg_completion) or (usage.get("total_tokens") if usage else None),
            "api_calls": api_calls,
        }

        response = LLMResponse(
            content=content,
            usage=usage,
            model=model_str,
            latency_ms=latency_ms,
            raw_response=None,
        )

        if self.llm_logger:
            self.llm_logger.log_call(
                LLMCallRecord(
                    model=model_str,
                    purpose=purpose,
                    messages=messages,
                    response_content=content,
                    usage=usage,
                    latency_ms=latency_ms,
                )
            )

        logger.info(
            "llm_call_complete",
            model=model_str,
            purpose=purpose,
            latency_ms=latency_ms,
            tokens=usage.get("total_tokens"),
        )
        return response

    async def generate_text(
        self,
        prompt: str,
        *,
        system: str = "",
        purpose: str = "",
    ) -> str:
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = await self.generate(messages, purpose=purpose)
        return response.content

    async def generate_json(
        self,
        messages: list[dict],
        model_class: type[BaseModel],
        *,
        purpose: str = "",
        retries: int = 1,
    ) -> BaseModel:
        base_messages = list(messages)
        attempt_messages = base_messages
        last_error: Exception | None = None
        for attempt in range(1 + retries):
            rf = {"type": "json_object"} if self.config.json_response_format is not False else None
            response = await self.generate(
                attempt_messages,
                purpose=purpose,
                temperature=0.0,
                response_format=rf,
            )
            try:
                return model_class.model_validate(loads_json(response.content))
            except (json.JSONDecodeError, ValueError) as exc:
                last_error = exc
                logger.warning(
                    "json_parse_failed",
                    purpose=purpose,
                    attempt=attempt + 1,
                    error=str(exc),
                )
                if attempt < retries:
                    attempt_messages = base_messages + [
                        {"role": "assistant", "content": extract_json(response.content)[:2000]},
                        {
                            "role": "user",
                            "content": (
                                f"JSON parse error: {exc}\n\n"
                                "Respond with ONLY the raw JSON object. No markdown fences, "
                                "no trailing commas, no comments, no text before or after the JSON."
                            ),
                        },
                    ]
        raise LLMError(f"Failed to parse JSON after {1 + retries} attempts: {last_error}")
