from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from uuid import uuid4

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp


logger = logging.getLogger("live_chain_defense.security")


@dataclass(frozen=True)
class SecurityOptions:
    environment: str
    auth_required: bool
    api_keys: tuple[str, ...]
    exempt_paths: tuple[str, ...]
    rate_limit_per_minute: int
    rate_limit_exempt_paths: tuple[str, ...]


class AuthMiddleware:
    def __init__(self, app: ASGIApp, options: SecurityOptions) -> None:
        self.app = app
        self.options = options
        self.valid_keys = {key for key in options.api_keys if key}

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path

        if _path_is_exempt(path, self.options.exempt_paths):
            await self.app(scope, receive, send)
            return

        if not self.options.auth_required:
            await self.app(scope, receive, send)
            return

        if not self.valid_keys:
            if self.options.environment.lower() == "production":
                response = JSONResponse(
                    status_code=503,
                    content={"detail": "service misconfigured: missing API keys"},
                )
                await response(scope, receive, send)
                return
            await self.app(scope, receive, send)
            return

        provided = _extract_api_key(request)
        if not provided or provided not in self.valid_keys:
            response = JSONResponse(status_code=401, content={"detail": "unauthorized"})
            await response(scope, receive, send)
            return

        scope.setdefault("state", {})["api_key"] = provided
        await self.app(scope, receive, send)


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, options: SecurityOptions) -> None:
        self.app = app
        self.options = options
        self.lock = threading.Lock()
        self.buckets: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path

        if _path_is_exempt(path, self.options.rate_limit_exempt_paths):
            await self.app(scope, receive, send)
            return

        limit = self.options.rate_limit_per_minute
        if limit <= 0:
            await self.app(scope, receive, send)
            return

        identifier = _extract_api_key(request) or request.client.host if request.client else "unknown"
        now = time.time()
        cutoff = now - 60.0
        limited = False

        with self.lock:
            bucket = self.buckets[identifier]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                limited = True
            else:
                bucket.append(now)

        if limited:
            response = JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message) -> None:  # type: ignore[no-untyped-def]
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                csp = (
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "style-src 'self' https://fonts.googleapis.com; "
                    "font-src 'self' https://fonts.gstatic.com data:; "
                    "img-src 'self' data:; "
                    "connect-src 'self'; "
                    "object-src 'none'; "
                    "base-uri 'none'; "
                    "frame-ancestors 'none'"
                )
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"geolocation=(), camera=(), microphone=()"),
                        (b"content-security-policy", csp.encode("utf-8")),
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
                    ]
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        request_id = str(uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_wrapper(message) -> None:  # type: ignore[no-untyped-def]
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((b"x-request-id", request_id.encode("utf-8")))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            method = scope.get("method", "")
            path = scope.get("path", "")
            logger.info("request complete", extra={"request_id": request_id, "method": method, "path": path, "elapsed_ms": round(elapsed_ms, 3)})


def _extract_api_key(request: Request) -> str | None:
    api_key = request.headers.get("x-api-key")
    if api_key:
        return api_key.strip()

    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()

    return None


def _path_is_exempt(path: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            if path.startswith(prefix):
                return True
            continue
        if path == pattern:
            return True
    return False


def install_security_middlewares(app: ASGIApp, options: SecurityOptions) -> None:
    # Order matters: request context -> rate limit -> auth -> security headers.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuthMiddleware, options=options)
    app.add_middleware(RateLimitMiddleware, options=options)
    app.add_middleware(RequestContextMiddleware)
