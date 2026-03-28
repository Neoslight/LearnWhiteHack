"""Tests du module core/rate_limiter.py."""

from __future__ import annotations

import time

from learnwhitehack.core.rate_limiter import RateLimiter, jitter, shuffle_ports


def test_jitter_within_range():
    """jitter() attend une durée dans [min, max]."""
    start = time.monotonic()
    jitter(0.0, 0.05)
    elapsed = time.monotonic() - start
    assert elapsed < 0.15  # marge pour les systèmes lents


def test_shuffle_ports_same_elements():
    """shuffle_ports() retourne les mêmes éléments dans un ordre possiblement différent."""
    ports = list(range(1, 101))
    shuffled = shuffle_ports(ports)
    assert sorted(shuffled) == ports
    assert len(shuffled) == len(ports)


def test_shuffle_ports_does_not_mutate():
    """shuffle_ports() ne modifie pas la liste originale."""
    ports = [80, 443, 22]
    original = list(ports)
    shuffle_ports(ports)
    assert ports == original


def test_rate_limiter_context_manager():
    """RateLimiter.acquire() s'exécute sans erreur."""
    rl = RateLimiter(min_delay=0.0, max_delay=0.01)
    with rl.acquire():
        result = 42
    assert result == 42
