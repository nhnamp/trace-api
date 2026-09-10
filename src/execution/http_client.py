from __future__ import annotations

import time
from typing import Any

import structlog

from src.models.evidence import HTTPResponseCapture

logger = structlog.get_logger(__name__)


class HTTPClientError(Exception):
    pass


class HTTPClient:
    def __init__(
        self,
        *,
        timeout: float = 30.0,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        max_response_body_bytes: int = 512 * 1024,
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.max_response_body_bytes = max_response_body_bytes

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        body: str | bytes | None = None,
        json_body: Any = None,
        timeout: float | None = None,
    ) -> HTTPResponseCapture:
        import httpx

        effective_timeout = timeout or self.timeout
        request_headers = dict(headers) if headers else {}

        logger.info(
            "http_request",
            method=method.upper(),
            url=url,
            has_body=body is not None or json_body is not None,
            timeout=effective_timeout,
        )

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                timeout=effective_timeout,
            ) as client:
                kwargs: dict[str, Any] = {
                    "method": method.upper(),
                    "url": url,
                    "headers": request_headers,
                }
                if params:
                    kwargs["params"] = params
                if json_body is not None:
                    kwargs["json"] = json_body
                elif body is not None:
                    kwargs["content"] = body

                response = await client.request(**kwargs)
        except httpx.TimeoutException as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "http_timeout",
                method=method.upper(),
                url=url,
                duration_ms=duration_ms,
            )
            raise HTTPClientError(f"HTTP request timed out after {effective_timeout}s: {exc}") from exc
        except httpx.RequestError as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.error(
                "http_request_error",
                method=method.upper(),
                url=url,
                error=str(exc),
                duration_ms=duration_ms,
            )
            raise HTTPClientError(f"HTTP request failed: {exc}") from exc

        duration_ms = int((time.monotonic() - start) * 1000)

        response_headers = dict(response.headers)
        content_type = response.headers.get("content-type", "")

        body_bytes = response.content
        if len(body_bytes) > self.max_response_body_bytes:
            body_text = body_bytes[: self.max_response_body_bytes].decode(
                "utf-8", errors="replace"
            ) + "\n... [body truncated]"
        else:
            body_text = body_bytes.decode("utf-8", errors="replace")

        capture = HTTPResponseCapture(
            status_code=response.status_code,
            headers=response_headers,
            body=body_text,
            content_type=content_type,
        )

        logger.info(
            "http_response",
            method=method.upper(),
            url=url,
            status_code=response.status_code,
            content_type=content_type,
            body_length=len(body_bytes),
            duration_ms=duration_ms,
        )

        return capture

    async def get(self, url: str, **kwargs: Any) -> HTTPResponseCapture:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HTTPResponseCapture:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HTTPResponseCapture:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> HTTPResponseCapture:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HTTPResponseCapture:
        return await self.request("DELETE", url, **kwargs)
