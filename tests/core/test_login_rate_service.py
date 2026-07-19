"""Login rate limiter ownership and window behavior tests."""

import pytest

from anteumbra.application.login_rate_service import LoginRateLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_limiter_blocks_after_configured_attempts_and_resets_after_window():
    clock = Clock()
    limiter = LoginRateLimiter(window_seconds=60, max_attempts=5, clock=clock)

    assert all(limiter.check_and_record("192.0.2.1").allowed for _ in range(5))
    blocked = limiter.check_and_record("192.0.2.1")

    assert blocked.allowed is False
    assert blocked.retry_after_seconds == 60

    clock.now += 60
    assert limiter.check_and_record("192.0.2.1").allowed is True


def test_reset_clears_one_client_without_affecting_another():
    limiter = LoginRateLimiter(max_attempts=1)
    assert limiter.check_and_record("alpha").allowed
    assert limiter.check_and_record("beta").allowed

    limiter.reset("alpha")

    assert limiter.check_and_record("alpha").allowed
    assert limiter.check_and_record("beta").allowed is False


def test_runtime_instances_do_not_share_attempts():
    first = LoginRateLimiter(max_attempts=1)
    second = LoginRateLimiter(max_attempts=1)

    assert first.check_and_record("same-client").allowed
    assert first.check_and_record("same-client").allowed is False
    assert second.check_and_record("same-client").allowed


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"window_seconds": 0}, "window_seconds"),
        ({"max_attempts": 0}, "max_attempts"),
    ],
)
def test_invalid_limits_are_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        LoginRateLimiter(**kwargs)
