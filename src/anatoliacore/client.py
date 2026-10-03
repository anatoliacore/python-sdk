from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


@dataclass
class AnatoliaCoreError(RuntimeError):
    message: str
    status_code: int | None = None
    code: str = "request_failed"
    request_id: str | None = None
    retryable: bool = False
    retry_after: int | None = None

    def __str__(self) -> str:
        suffix = f" (request_id={self.request_id})" if self.request_id else ""
        return f"{self.message}{suffix}"


@dataclass(frozen=True)
class ApiResponse:
    data: Any
    operation_id: str | None = None
    operation_location: str | None = None


def verify_webhook(
    *,
    secret: str,
    body: bytes,
    webhook_id: str,
    timestamp: str,
    signature: str,
    tolerance_seconds: int = 300,
    now_seconds: int | None = None,
) -> dict[str, Any]:
    """Verify an AnatoliaCore webhook before parsing or acting on it."""
    if not secret.startswith("whsec_") or not webhook_id or len(body) > 2 * 1024 * 1024:
        raise ValueError("invalid webhook verification input")
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid webhook timestamp") from exc
    current = int(time.time()) if now_seconds is None else now_seconds
    if tolerance_seconds < 0 or abs(current - sent_at) > tolerance_seconds:
        raise ValueError("webhook timestamp is outside the allowed tolerance")
    expected = "v1=" + hmac.new(
        secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid webhook signature")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid webhook JSON") from exc
    if not isinstance(payload, dict) or payload.get("id") != webhook_id:
        raise ValueError("webhook id does not match the signed payload")
    return payload


class AnatoliaCore:
    _MAX_RESPONSE_BYTES = 2 * 1024 * 1024

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://console.anatoliacore.com/api/public/v1",
        timeout: float = 30.0,
        allow_insecure: bool = False,
        opener=None,
    ):
        parsed = urlsplit(base_url)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must be an absolute URL without credentials, query or fragment")
        if parsed.scheme != "https" and not (
            allow_insecure and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("base_url must use HTTPS")
        if not api_key.startswith("ac_live_") or len(api_key) > 256:
            raise ValueError("api_key has an invalid format")
        if not 1 <= timeout <= 300:
            raise ValueError("timeout must be between 1 and 300 seconds")
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        return self.request_with_metadata(
            method,
            path,
            body=body,
            params=params,
            idempotency_key=idempotency_key,
            headers=headers,
        ).data

    def request_with_metadata(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> ApiResponse:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an API-relative absolute path")
        query = ""
        if params:
            clean = {key: value for key, value in params.items() if value is not None}
            query = "?" + urlencode(clean)
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "anatoliacore-python/1.0.0",
            "X-API-Key": self._api_key,
        }
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            request_headers["Idempotency-Key"] = idempotency_key or str(uuid.uuid4())
        for name, value in (headers or {}).items():
            if name.lower() not in {"x-confirm-resource-name"} or not value or len(value) > 255:
                raise ValueError("unsupported or invalid request header")
            request_headers[name] = value
        request = Request(self.base_url + path + query, data=payload, headers=request_headers, method=method.upper())
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                content = response.read(self._MAX_RESPONSE_BYTES + 1)
                if len(content) > self._MAX_RESPONSE_BYTES:
                    raise AnatoliaCoreError("API response exceeded the safe size limit", status_code=response.status)
                operation_id = response.headers.get("X-Operation-ID")
                operation_location = response.headers.get("Operation-Location")
                if not content or response.status == 204:
                    return ApiResponse(None, operation_id, operation_location)
                if "application/json" not in response.headers.get("Content-Type", ""):
                    raise AnatoliaCoreError("API returned an unexpected content type", status_code=response.status)
                return ApiResponse(json.loads(content), operation_id, operation_location)
        except HTTPError as exc:
            self._raise_http_error(exc)
        except (URLError, TimeoutError, OSError) as exc:
            raise AnatoliaCoreError(
                "Could not reach the AnatoliaCore API",
                code="network_error",
                retryable=True,
            ) from exc

    @staticmethod
    def _raise_http_error(exc: HTTPError) -> None:
        try:
            payload = json.loads(exc.read(AnatoliaCore._MAX_RESPONSE_BYTES + 1))
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        error = payload.get("error") if isinstance(payload, dict) else {}
        error = error if isinstance(error, dict) else {}
        retry_after_value = exc.headers.get("Retry-After")
        try:
            retry_after = int(retry_after_value) if retry_after_value else None
        except ValueError:
            retry_after = None
        message = error.get("message") or (payload.get("detail") if isinstance(payload, dict) else None)
        raise AnatoliaCoreError(
            str(message or "AnatoliaCore API request failed"),
            status_code=exc.code,
            code=str(error.get("code") or "request_failed"),
            request_id=error.get("request_id"),
            retryable=bool(error.get("retryable", exc.code >= 500)),
            retry_after=retry_after,
        ) from exc

    def list_instances(self, *, page: int = 1, per_page: int = 20, status: str | None = None) -> list[dict]:
        return self.request("GET", "/instances", params={"page": page, "per_page": per_page, "status": status})

    def get_instance(self, instance_id: str) -> dict:
        return self.request("GET", f"/instances/{quote(instance_id, safe='')}")

    def create_instance(self, data: dict[str, Any], *, idempotency_key: str | None = None) -> dict:
        return self.request("POST", "/instances", body=data, idempotency_key=idempotency_key)

    def power_instance(self, instance_id: str, action: str, *, idempotency_key: str | None = None) -> dict:
        return self.request(
            "POST",
            f"/instances/{quote(instance_id, safe='')}/power",
            body={"action": action},
            idempotency_key=idempotency_key,
        )

    def delete_instance(
        self,
        instance_id: str,
        *,
        confirmation_name: str,
        idempotency_key: str | None = None,
    ) -> Any:
        return self.request(
            "DELETE",
            f"/instances/{quote(instance_id, safe='')}",
            idempotency_key=idempotency_key,
            headers={"X-Confirm-Resource-Name": confirmation_name},
        )

    def list_vdcs(self, *, page: int = 1, per_page: int = 20) -> list[dict]:
        return self.request("GET", "/vdcs", params={"page": page, "per_page": per_page})

    def create_vdc(self, data: dict[str, Any], *, idempotency_key: str | None = None) -> dict:
        return self.request("POST", "/vdcs", body=data, idempotency_key=idempotency_key)

    def list_instance_types(self) -> list[dict]:
        return self.request("GET", "/instance-types")

    def get_operation(self, operation_id: str) -> dict:
        return self.request("GET", f"/operations/{quote(operation_id, safe='')}")

    def wait_operation(self, operation_id: str, *, timeout: float = 300.0) -> dict:
        deadline = time.monotonic() + timeout
        delay = 0.5
        while True:
            operation = self.get_operation(operation_id)
            if operation.get("status") in {"succeeded", "failed", "needs_attention", "cancelled"}:
                return operation
            if time.monotonic() >= deadline:
                raise AnatoliaCoreError("Timed out waiting for operation", code="operation_timeout", retryable=True)
            time.sleep(delay)
            delay = min(delay * 1.7, 5.0)

    def cancel_operation(self, operation_id: str, *, idempotency_key: str | None = None) -> dict:
        return self.request(
            "POST",
            f"/operations/{quote(operation_id, safe='')}/cancel",
            idempotency_key=idempotency_key,
        )
