from __future__ import annotations

import tiktoken

_RESERVE_TOKENS = 256

_ENCODER = None


def _encoder():
    global _ENCODER
    if _ENCODER is None:
        _ENCODER = tiktoken.get_encoding("cl100k_base")
    return _ENCODER


def count_tokens(text: str) -> int:
    if not text:
        return 0
    return len(_encoder().encode(text))


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    if max_tokens <= 0 or not text:
        return ""
    enc = _encoder()
    toks = enc.encode(text)
    if len(toks) <= max_tokens:
        return text
    marker = "\n...[truncated to fit context]..."
    keep = max(0, max_tokens - count_tokens(marker))
    return enc.decode(toks[:keep]) + marker


def prompt_token_budget(context_window: int, max_completion_tokens: int) -> int:
    return max(0, context_window - max_completion_tokens - _RESERVE_TOKENS)


def allocate_blocks(blocks: list[str], budget: int) -> list[str]:
    out: list[str] = []
    remaining = budget
    for block in blocks:
        if remaining <= 0:
            out.append("")
            continue
        needed = count_tokens(block)
        if needed <= remaining:
            out.append(block)
            remaining -= needed
        else:
            out.append(truncate_to_tokens(block, remaining))
            remaining = 0
    return out
