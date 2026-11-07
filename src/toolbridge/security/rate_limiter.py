"""Sliding window rate limiter for protecting ToolBridge from excessive requests."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class RateLimitExceededError(Exception):
    """Raised when an API caller exceeds their allocated rate limit."""
    def __init__(self, message: str, retry_after: float) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter per caller key."""

    def __init__(self, max_requests_per_minute: int = 60) -> None:
        self.max_requests = max_requests_per_minute
        self.window_seconds = 60.0
        self._history: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check_rate_limit(self, key: str) -> None:
        """Check if caller key is within rate limits. Raises RateLimitExceededError if violated."""
        now = time.time()
        window_start = now - self.window_seconds

        async with self._lock:
            # Purge timestamps outside sliding window
            timestamps = [t for t in self._history[key] if t > window_start]
            self._history[key] = timestamps

            if len(timestamps) >= self.max_requests:
                oldest = timestamps[0]
                retry_after = max(0.1, round(self.window_seconds - (now - oldest), 1))
                raise RateLimitExceededError(
                    f"Rate limit exceeded: Maximum {self.max_requests} requests per minute.",
                    retry_after=retry_after,
                )

            # Record this request
            self._history[key].append(now)
