"""Retry/backoff helper usable with any of the freetls transports."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass

_RETRYABLE = (OSError,)


@dataclass
class Retry:
    """Retry policy: attempt count, exponential backoff and retryable statuses."""

    total: int = 3
    backoff: float = 0.5
    max_backoff: float = 8.0
    jitter: bool = True
    status_forcelist: tuple = (429, 500, 502, 503, 504)
    retry_on: tuple = _RETRYABLE

    def delay(self, attempt: int, rng: random.Random | None = None) -> float:
        base = min(self.backoff * (2**attempt), self.max_backoff)
        if self.jitter:
            base = base * (0.5 + (rng or random).random() * 0.5)
        return base

    def should_retry_status(self, status: int) -> bool:
        return status in self.status_forcelist

    def run(self, fn, *, sleep=time.sleep, on_status=None, rng: random.Random | None = None):
        """Call ``fn`` until it succeeds, the status is final, or attempts run out.

        ``fn`` may return a response whose ``status_code`` is inspected when
        ``on_status`` is truthy.
        """
        last_exc: Exception | None = None
        for attempt in range(max(1, self.total)):
            try:
                result = fn()
            except self.retry_on as exc:  # noqa: B014 - configurable tuple
                last_exc = exc
            else:
                if not on_status or not self.should_retry_status(getattr(result, "status_code", 0)):
                    return result
            if attempt + 1 < max(1, self.total):
                sleep(self.delay(attempt, rng))
        if last_exc is not None:
            raise last_exc
        return result
