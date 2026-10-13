"""Optional API-key auth + in-memory rate limiting for the local deployment scope."""
from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings

RATE_LIMITED_PREFIXES = ("/api/v1/analyze", "/api/v1/evaluations/run", "/api/v1/replay", "/api/v1/demo")


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.hits: dict[str, deque] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and request.method != "OPTIONS":
            if settings.api_key and path != "/api/v1/health":
                supplied = request.headers.get("x-api-key", "")
                if not hmac.compare_digest(supplied, settings.api_key):
                    return JSONResponse({"detail": "missing or invalid X-API-Key"}, status_code=401)
            if request.method == "POST" and path.startswith(RATE_LIMITED_PREFIXES):
                key = request.client.host if request.client else "unknown"
                q = self.hits[key]
                now = time.time()
                while q and now - q[0] > 60:
                    q.popleft()
                if len(q) >= settings.rate_limit_per_min:
                    return JSONResponse({"detail": f"rate limit exceeded ({settings.rate_limit_per_min}/min)"}, status_code=429,
                                        headers={"Retry-After": "60"})
                q.append(now)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
