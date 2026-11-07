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
