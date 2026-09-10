from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

import httpx
import structlog
from pydantic import BaseModel

from src.config.settings import CVELookupConfig
from src.knowledge.rag_engine import CVEDocument
from src.llm.client import LLMClient

logger = structlog.get_logger(__name__)


SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low"]

_PRODUCT_CACHE: dict[str, list["CVELookupResult"]] = {}
_throttle_until: float = 0.0
_THROTTLE_MAX_SECONDS: float = 900.0


def clear_lookup_cache() -> None:
    global _throttle_until
    _PRODUCT_CACHE.clear()
    _throttle_until = 0.0

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "": 0,
    "none": 0,
}


class OpenCVEError(Exception):
    pass


class CVELookupResult(BaseModel):
    cve_id: str
    description: str = ""
    title: str = ""
    severity: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    weaknesses: list[str] = []
    vendors: list[str] = []
    source_query: str = ""
    raw: dict = {}

    def rank_key(self) -> tuple[int, float]:
        return (_SEVERITY_RANK.get(self.severity.lower(), 0), self.cvss_score or 0.0)

    def to_cve_document(self) -> CVEDocument:
        return CVEDocument(
            doc_id=f"opencve:{self.cve_id}",
            cve_id=self.cve_id,
            title=self.title or self.cve_id,
            description=self.description,
            vulnerability_type=", ".join(self.weaknesses),
            affected_component=", ".join(self.vendors[:5]),
            target_library=self.vendors[0] if self.vendors else None,
            source=f"opencve[{self.source_query}]",
        )


class OpenCVEClient:
    def __init__(self, config: CVELookupConfig) -> None:
        self.config = config
        self._base_url = config.base_url.rstrip("/")
        self._headers: dict[str, str] = {"Accept": "application/json"}
        token = config.resolved_token()
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        else:
            logger.warning(
                "opencve_no_auth",
                message="cve_lookup.token not set in config — requests may fail with 401",
            )

    async def list_cves(
        self,
        *,
        vendor: str | None = None,
        product: str | None = None,
        search: str | None = None,
        cvss: str | None = None,
        page: int = 1,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page}
        if vendor:
            params["vendor"] = vendor
        if product:
            params["product"] = product
        if search:
            params["search"] = search
        if cvss:
            params["cvss"] = cvss

        return await self._request("GET", "/cve", params=params)

    async def get_cve(self, cve_id: str, *, include: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if include:
            params["include"] = include
        return await self._request("GET", f"/cve/{cve_id}", params=params)

    @staticmethod
    def is_throttled() -> bool:
        return time.monotonic() < _throttle_until

    @staticmethod
    def _enter_cooldown(seconds: float) -> None:
        global _throttle_until
        seconds = max(0.0, min(seconds, _THROTTLE_MAX_SECONDS))
        until = time.monotonic() + seconds
        if until > _throttle_until:
            _throttle_until = until
            logger.warning(
                "opencve_throttle_cooldown",
                seconds=round(seconds),
                message="OpenCVE rate-limited (429); skipping lookups until cooldown ends",
            )

    @staticmethod
    def _parse_retry_after(resp: httpx.Response) -> float:
        ra = resp.headers.get("Retry-After")
        if ra and ra.strip().isdigit():
            return float(ra.strip())
        m = re.search(r"available in (\d+)\s*second", resp.text)
        if m:
            return float(m.group(1))
        return 120.0

    async def _request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self.is_throttled():
            raise OpenCVEError("OpenCVE in throttle cooldown — request skipped")

        url = f"{self._base_url}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds, headers=self._headers
            ) as client:
                resp = await client.request(method, url, params=params)
        except httpx.RequestError as exc:
            raise OpenCVEError(f"Network error calling {url}: {exc}") from exc

        if resp.status_code == 404:
            return {}
        if resp.status_code == 429:
            self._enter_cooldown(self._parse_retry_after(resp))
            raise OpenCVEError(
                f"OpenCVE 429 for {method} {path} params={params}: {resp.text[:200]}"
            )
        if resp.status_code >= 400:
            raise OpenCVEError(
                f"OpenCVE {resp.status_code} for {method} {path} "
                f"params={params}: {resp.text[:200]}"
            )

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise OpenCVEError(f"OpenCVE returned non-JSON body: {exc}") from exc


class CVELookupService:
    def __init__(
        self,
        client: OpenCVEClient,
        config: CVELookupConfig,
        llm_client: LLMClient | None = None,
    ) -> None:
        self.client = client
        self.config = config
        self.llm_client = llm_client

    async def lookup_by_product(self, product_name: str) -> list[CVELookupResult]:
        product_name = product_name.strip()
        if not product_name:
            return []

        cache_key = product_name.lower()
        if cache_key in _PRODUCT_CACHE:
            logger.debug("cve_lookup_cache_hit", product=product_name)
            return _PRODUCT_CACHE[cache_key]

        if OpenCVEClient.is_throttled():
            logger.debug("cve_lookup_skipped_cooldown", product=product_name)
            return []

        results = await self._lookup_single_name(product_name)

        if not results and self.config.use_llm_alt_names and self.llm_client is not None:
            alt_names = await self._generate_alt_names(product_name)
            logger.info(
                "cve_lookup_alt_names",
                product=product_name,
                alt_names=alt_names,
            )
            for alt in alt_names[: self.config.max_alt_names]:
                if alt.lower() == product_name.lower():
                    continue
                alt_results = await self._lookup_single_name(alt)
                results = self._merge_unique(results, alt_results)
                if len(results) >= self.config.max_cves_per_product:
                    break

        results = await self._enrich_top(results)
        results.sort(key=lambda r: r.rank_key(), reverse=True)
        results = results[: self.config.max_cves_per_product]

        if not OpenCVEClient.is_throttled():
            _PRODUCT_CACHE[cache_key] = results
        return results

    async def _lookup_single_name(self, name: str) -> list[CVELookupResult]:
        aggregated: dict[str, CVELookupResult] = {}
        for severity in SEVERITY_ORDER:
            for query_kind in ("vendor", "search"):
                try:
                    resp = await self.client.list_cves(
                        vendor=name if query_kind == "vendor" else None,
                        search=name if query_kind == "search" else None,
                        cvss=severity,
                    )
                except OpenCVEError as exc:
                    logger.warning(
                        "cve_lookup_query_failed",
                        name=name,
                        severity=severity,
                        query_kind=query_kind,
                        error=str(exc),
                    )
                    continue

                for item in resp.get("results", []) or []:
                    cve_id = item.get("cve_id") or item.get("id")
                    if not cve_id or cve_id in aggregated:
                        continue
                    aggregated[cve_id] = CVELookupResult(
                        cve_id=cve_id,
                        description=item.get("description", "") or "",
                        severity=severity,
                        source_query=f"{query_kind}={name}&cvss={severity}",
                        raw=item,
                    )

                if len(aggregated) >= self.config.max_cves_per_product * 2:
                    return list(aggregated.values())
        return list(aggregated.values())

    async def _enrich_top(
        self, results: list[CVELookupResult]
    ) -> list[CVELookupResult]:
        if not results or self.config.fetch_detail_for_top_k <= 0:
            return results
        results.sort(key=lambda r: r.rank_key(), reverse=True)
        top = results[: self.config.fetch_detail_for_top_k]
        details = await asyncio.gather(
            *(self._fetch_detail(r.cve_id) for r in top),
            return_exceptions=True,
        )
        for r, detail in zip(top, details, strict=True):
            if isinstance(detail, Exception) or not detail:
                continue
            self._apply_detail(r, detail)
        return results

    async def _fetch_detail(self, cve_id: str) -> dict[str, Any] | None:
        try:
            return await self.client.get_cve(cve_id)
        except OpenCVEError as exc:
            logger.warning("cve_detail_failed", cve_id=cve_id, error=str(exc))
            return None

    @staticmethod
    def _apply_detail(result: CVELookupResult, detail: dict[str, Any]) -> None:
        result.title = detail.get("title", "") or result.title
        if detail.get("description"):
            result.description = detail["description"]
        metrics = detail.get("metrics", {}) or {}
        cvss_data = (metrics.get("cvssV3_1") or {}).get("data") or {}
        if not cvss_data:
            cvss_data = (metrics.get("cvssV3_0") or {}).get("data") or {}
        if not cvss_data:
            cvss_data = (metrics.get("cvssV4_0") or {}).get("data") or {}
        score = cvss_data.get("score")
        if isinstance(score, (int, float)):
            result.cvss_score = float(score)
            if not result.severity:
                result.severity = _score_to_severity(float(score))
        vector = cvss_data.get("vector")
        if isinstance(vector, str):
            result.cvss_vector = vector
        weaknesses = detail.get("weaknesses") or []
        if isinstance(weaknesses, list):
            result.weaknesses = [w for w in weaknesses if isinstance(w, str)]
        vendors = detail.get("vendors") or []
        if isinstance(vendors, list):
            result.vendors = [
                v for v in vendors if isinstance(v, str) and "$PRODUCT$" not in v
            ]

    @staticmethod
    def _merge_unique(
        base: list[CVELookupResult], extras: list[CVELookupResult]
    ) -> list[CVELookupResult]:
        seen = {r.cve_id for r in base}
        for r in extras:
            if r.cve_id not in seen:
                base.append(r)
                seen.add(r.cve_id)
        return base

    async def _generate_alt_names(self, product_name: str) -> list[str]:
        if self.llm_client is None:
            return []
        prompt = (
            "You are helping search a CVE database that indexes vulnerabilities by "
            "vendor/product name. The initial name returned no results.\n\n"
            f"Initial name: {product_name!r}\n\n"
            "Generate alternative names that a CVE database might use for the same "
            "product/service. Consider:\n"
            "- The parent project name (e.g. plugin → main framework)\n"
            "- Vendor / organization name\n"
            "- Common short forms and aliases\n"
            "- Underlying library the service is built on\n\n"
            "Respond with ONLY a JSON object of the form:\n"
            '{"names": ["<name1>", "<name2>", ...]}\n'
            f"Provide at most {self.config.max_alt_names} names, ordered by likelihood."
        )
        try:
            response = await self.llm_client.generate_text(
                prompt, purpose="cve_lookup_alt_names"
            )
        except Exception as exc:  # noqa: BLE001 — LLM failure must not crash lookup
            logger.warning("cve_lookup_alt_names_llm_failed", error=str(exc))
            return []

        from src.llm.client import extract_json

        try:
            data = json.loads(extract_json(response))
        except json.JSONDecodeError as exc:
            logger.warning("cve_lookup_alt_names_parse_failed", error=str(exc))
            return []

        names = data.get("names") if isinstance(data, dict) else None
        if not isinstance(names, list):
            return []
        cleaned: list[str] = []
        for n in names:
            if isinstance(n, str) and n.strip():
                cleaned.append(n.strip())
        return cleaned


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return ""
