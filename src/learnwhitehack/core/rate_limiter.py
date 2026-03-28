"""Rate limiter avec jitter aléatoire pour éviter les patterns de requêtes réguliers."""

from __future__ import annotations

import random
import time
from contextlib import contextmanager
from typing import Generator


def jitter(min_sec: float = 1.0, max_sec: float = 3.5) -> None:
    """Attend une durée aléatoire entre min_sec et max_sec secondes."""
    delay = random.uniform(min_sec, max_sec)
    time.sleep(delay)


def shuffle_ports(ports: list[int]) -> list[int]:
    """Retourne la liste de ports dans un ordre aléatoire."""
    shuffled = ports.copy()
    random.shuffle(shuffled)
    return shuffled


class RateLimiter:
    """Context manager pour espacer les requêtes avec jitter."""

    def __init__(self, min_delay: float = 1.0, max_delay: float = 3.5) -> None:
        self.min_delay = min_delay
        self.max_delay = max_delay
        self._last_call: float = 0.0

    @contextmanager
    def acquire(self) -> Generator[None, None, None]:
        """Attend le délai nécessaire avant d'exécuter le bloc."""
        elapsed = time.monotonic() - self._last_call
        needed = random.uniform(self.min_delay, self.max_delay)
        if elapsed < needed:
            time.sleep(needed - elapsed)
        try:
            yield
        finally:
            self._last_call = time.monotonic()

    def wait(self) -> None:
        """Alias simple pour attendre le jitter sans context manager."""
        jitter(self.min_delay, self.max_delay)
