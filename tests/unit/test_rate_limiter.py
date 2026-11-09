"""Unit tests for SlidingWindowRateLimiter."""
import pytest
from toolbridge.security.rate_limiter import RateLimitExceededError, SlidingWindowRateLimiter


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rate_limiter_allows_under_limit():
    """Verify requests under the threshold succeed."""
    limiter = SlidingWindowRateLimiter(max_requests_per_minute=5)
    for _ in range(5):
        await limiter.check_rate_limit("test_caller")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rate_limiter_blocks_over_limit():
    """Verify exceeding limit raises RateLimitExceededError with retry_after."""
    limiter = SlidingWindowRateLimiter(max_requests_per_minute=3)
    for _ in range(3):
        await limiter.check_rate_limit("user_1")

    with pytest.raises(RateLimitExceededError) as exc_info:
        await limiter.check_rate_limit("user_1")

    assert exc_info.value.retry_after > 0
    assert "Rate limit exceeded" in str(exc_info.value)

    # Different key has independent counter
    await limiter.check_rate_limit("user_2")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rate_limiter_evicts_expired_keys_under_high_cardinality():
    """Verify rate limiter periodically purges expired keys to prevent unbounded memory growth."""
    limiter = SlidingWindowRateLimiter(max_requests_per_minute=10)
    # Populate 1200 unique ephemeral callers with timestamps from the past
    old_time = 1000.0
    for i in range(1200):
        limiter._history[f"ephemeral_key_{i}"] = [old_time]

    assert len(limiter._history) == 1200

    # Next request triggers eviction since count > 1000
    await limiter.check_rate_limit("active_user")

    # All expired keys must have been evicted, keeping memory strictly bounded
    assert len(limiter._history) == 1
    assert "active_user" in limiter._history

