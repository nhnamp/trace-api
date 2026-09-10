from __future__ import annotations

import asyncio
from pathlib import Path

import structlog
from pydantic import BaseModel

from src.config.settings import DirEnumConfig

logger = structlog.get_logger(__name__)

DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "common_paths.txt"

_WILDCARD_SENTINEL = "wildcard0probe0zzq9x7k7q"

COMMON_PARAM_NAMES: tuple[str, ...] = (
    "path", "file", "filename", "filepath", "url", "uri", "dir", "directory",
    "folder", "page", "doc", "document", "template", "include", "view", "load",
    "read", "fetch", "download", "resource", "src", "source", "target", "dest",
    "destination", "redirect", "redir", "return", "returnurl", "next", "continue",
    "to", "out", "domain", "host", "site", "feed", "callback", "ref", "image",
    "img", "id", "name", "key", "query", "q", "search", "data", "input", "content",
    "action", "cmd", "exec", "func",
)


class DirEnumResult(BaseModel):
    path: str
    url: str
    status_code: int
    content_type: str = ""
    content_length: int = 0


class BypassProbeResult(BaseModel):
    base: str
    candidate: str
    vector: str
    path: str
    status_code: int
    body_excerpt: str = ""


_BYPASS_FORMS: tuple[str, ...] = (
    "..%2f{c}/",
    "%2e%2e%2f{c}/",
    "..%2f..%2f{c}/",
    "..%2f{c}",
)


def load_wordlist(path: str | Path | None, limit: int) -> list[str]:
    wl_path = Path(path) if path else DEFAULT_WORDLIST
    if not wl_path.exists():
        logger.warning("wordlist_not_found", path=str(wl_path))
        return []

    entries: list[str] = []
    seen: set[str] = set()
    for raw in wl_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry = line.lstrip("/")
        if entry and entry not in seen:
            seen.add(entry)
            entries.append(entry)
        if len(entries) >= limit:
            break
    return entries


class DirEnumerator:
    def __init__(self, config: DirEnumConfig) -> None:
        self.config = config

    @staticmethod
    def _parent_of(entry: str) -> str:
        return entry.rsplit("/", 1)[0] if "/" in entry else ""

    @staticmethod
    async def _wildcard_signatures(get, parents: set[str]) -> dict[str, tuple[int, str]]:
        async def sig_for(parent: str):
            sentinel = f"{parent}/{_WILDCARD_SENTINEL}" if parent else _WILDCARD_SENTINEL
            resp = await get(sentinel)
            if resp is None or resp.status_code == 404:
                return parent, None
            return parent, (resp.status_code, resp.text)

        pairs = await asyncio.gather(*(sig_for(p) for p in sorted(parents)))
        return {p: sig for p, sig in pairs if sig is not None}

    async def probe_paths(self, base_url: str, entries: list[str]) -> list[DirEnumResult]:
        base = base_url.rstrip("/")
        entries = [e.strip("/") for e in dict.fromkeys(e for e in entries if e.strip("/"))]
        if not entries:
            return []

        import httpx

        semaphore = asyncio.Semaphore(self.config.concurrency)
        async with httpx.AsyncClient(
            timeout=self.config.timeout_seconds, verify=False, follow_redirects=False,
        ) as client:
            async def get(path: str):
                url = f"{base}/{path}" if path else base
                async with semaphore:
                    try:
                        return await client.get(url)
                    except Exception:
                        return None

            catchall = await self._wildcard_signatures(
                get, {self._parent_of(e) for e in entries}
            )

            async def probe(entry: str) -> DirEnumResult | None:
                resp = await get(entry)
                if resp is None or resp.status_code == 404:
                    return None
                sig = catchall.get(self._parent_of(entry))
                if sig is not None and (resp.status_code, resp.text) == sig:
                    return None
                return DirEnumResult(
                    path="/" + entry,
                    url=f"{base}/{entry}",
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    content_length=int(resp.headers.get("content-length", 0) or 0),
                )

            probed = await asyncio.gather(*(probe(e) for e in entries))

        results = [r for r in probed if r is not None]
        results.sort(key=lambda r: (r.status_code, r.path))
        logger.info(
            "dir_enum_probe_paths", base_url=base, probed=len(entries),
            found=len(results), wildcard_parents=len(catchall),
        )
        return results

    async def probe_params(
        self,
        base_url: str,
        path: str,
        param_names,
        sentinel: str = "apdisco7x7",
    ) -> list[str]:
        base = base_url.rstrip("/")
        url_path = "/" + path.strip("/")
        candidates = [p for p in dict.fromkeys(param_names) if p]
        if not candidates:
            return []

        import httpx

        semaphore = asyncio.Semaphore(self.config.concurrency)
        async with httpx.AsyncClient(
            timeout=self.config.timeout_seconds, verify=False, follow_redirects=False,
        ) as client:
            async def get(param: str):
                async with semaphore:
                    try:
                        return await client.get(f"{base}{url_path}?{param}={sentinel}")
                    except Exception:
                        return None

            baseline = await get("zzq9junkparam")
            if baseline is None:
                return []
            baseline2 = await get("qx7zjunkparam")
            base_status = baseline.status_code
            base_len = len(baseline.text)
            base_has_sentinel = sentinel in baseline.text
            jitter = abs(len(baseline2.text) - base_len) if baseline2 is not None else 0
            size_threshold = max(48, jitter * 2 + 32)

            async def check(param: str) -> str | None:
                resp = await get(param)
                if resp is None:
                    return None
                if resp.status_code != base_status:
                    return param
                if sentinel in resp.text and not base_has_sentinel:
                    return param
                if abs(len(resp.text) - base_len) > size_threshold:
                    return param
                return None

            checked = await asyncio.gather(*(check(p) for p in candidates))

        found = [p for p in checked if p]
        logger.info(
            "dir_enum_probe_params",
            base_url=base, path=url_path, probed=len(candidates), found=len(found),
        )
        return found

    async def probe_bypass(
        self, base_url: str, bases: list[str], candidates,
    ) -> list[BypassProbeResult]:
        base_url = base_url.rstrip("/")
        bases = [b.strip("/") for b in dict.fromkeys(b for b in bases if b and b.strip("/"))]
        bases = bases[: self.config.bypass_max_bases]
        candidates = [c.strip("/") for c in dict.fromkeys(c for c in candidates if c and c.strip("/"))]
        if not bases or not candidates:
            return []

        import httpx

        semaphore = asyncio.Semaphore(self.config.concurrency)
        async with httpx.AsyncClient(
            timeout=self.config.timeout_seconds, verify=False, follow_redirects=False,
        ) as client:
            async def get(path: str):
                url = f"{base_url}/{path}" if path else base_url
                async with semaphore:
                    try:
                        return await client.get(url)
                    except Exception:
                        return None

            async def signatures(b: str):
                own = await get(b)
                sentinel = await get(f"{b}/{_WILDCARD_SENTINEL}")
                own_sig = (own.status_code, own.text) if own is not None else None
                sigs = set()
                if own_sig is not None:
                    sigs.add(own_sig)
                if sentinel is not None and sentinel.status_code != 404:
                    sigs.add((sentinel.status_code, sentinel.text))
                return b, own_sig, sigs

            base_info = await asyncio.gather(*(signatures(b) for b in bases))
            fetchable = {b for b, own, _ in base_info if own is not None}
            public_sigs: set[tuple[int, str]] = set()
            for _, _, sigs in base_info:
                public_sigs |= sigs

            probes: list[tuple[str, str, str]] = []
            for form in _BYPASS_FORMS:
                for b in bases:
                    if b not in fetchable:
                        continue
                    for c in candidates:
                        probes.append((b, c, form))
            probes = probes[: self.config.bypass_max_probes]

            async def attempt(b: str, c: str, form: str) -> BypassProbeResult | None:
                rel = form.format(c=c)
                path = f"{b}/{rel}"
                r = await get(path)
                if r is None or r.status_code != 200:
                    return None
                if not r.text.strip():
                    return None
                if (r.status_code, r.text) in public_sigs:
                    return None
                return BypassProbeResult(
                    base="/" + b, candidate=c, vector=rel, path="/" + path,
                    status_code=r.status_code, body_excerpt=r.text[:200],
                )

            raw = await asyncio.gather(*(attempt(*p) for p in probes))

        hits: dict[tuple[str, str], BypassProbeResult] = {}
        for r in raw:
            if r is None:
                continue
            key = (r.base, r.candidate)
            if key not in hits:
                hits[key] = r
        results = list(hits.values())
        logger.info(
            "dir_enum_probe_bypass",
            base_url=base_url, probed=len(probes), found=len(results),
        )
        return results

    async def enumerate(self, base_url: str) -> list[DirEnumResult]:
        base = base_url.rstrip("/")
        entries = load_wordlist(self.config.wordlist_path, self.config.max_paths)
        if not entries:
            logger.warning("dir_enum_empty_wordlist")
            return []

        logger.info(
            "dir_enum_start",
            base_url=base,
            wordlist_size=len(entries),
            concurrency=self.config.concurrency,
        )

        import httpx

        interesting = set(self.config.interesting_status_codes)
        results: list[DirEnumResult] = []
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async with httpx.AsyncClient(
            timeout=self.config.timeout_seconds,
            verify=False,
            follow_redirects=False,
        ) as client:

            async def get(path: str):
                url = f"{base}/{path}" if path else base
                async with semaphore:
                    try:
                        return await client.get(url)
                    except Exception:
                        return None

            catchall = await self._wildcard_signatures(
                get, {self._parent_of(e) for e in entries}
            )

            async def probe(entry: str) -> DirEnumResult | None:
                resp = await get(entry)
                if resp is None or resp.status_code not in interesting:
                    return None
                sig = catchall.get(self._parent_of(entry))
                if sig is not None and (resp.status_code, resp.text) == sig:
                    return None
                return DirEnumResult(
                    path="/" + entry,
                    url=f"{base}/{entry}",
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    content_length=int(resp.headers.get("content-length", 0) or 0),
                )

            probed = await asyncio.gather(*(probe(e) for e in entries))

        results = [r for r in probed if r is not None]
        results.sort(key=lambda r: (r.status_code, r.path))
        results = results[: self.config.max_findings]

        logger.info(
            "dir_enum_complete",
            base_url=base,
            probed=len(entries),
            found=len(results),
            wildcard_parents=len(catchall),
        )
        return results


async def _cli_main(base_url: str, wordlist: str | None) -> None:
    config = DirEnumConfig()
    if wordlist:
        config = config.model_copy(update={"wordlist_path": wordlist})
    enumerator = DirEnumerator(config)
    results = await enumerator.enumerate(base_url)

    print(f"\nDirectory enumeration for {base_url}")
    print(f"  wordlist: {config.wordlist_path or DEFAULT_WORDLIST}")
    print(f"  found {len(results)} interesting paths:\n")
    if not results:
        print("  (nothing found — target may reject all probes or be down)")
        return
    print(f"  {'STATUS':6}  {'TYPE':24}  PATH")
    for r in results:
        ctype = (r.content_type or "").split(";")[0][:24]
        print(f"  {r.status_code:<6}  {ctype:24}  {r.path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m src.execution.dir_enum <base_url> [wordlist]")
        sys.exit(1)
    asyncio.run(_cli_main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
