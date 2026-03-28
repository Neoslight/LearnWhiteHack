"""Fixtures partagées pour les tests."""

from __future__ import annotations

import pytest
import responses as responses_lib

from learnwhitehack.core.config import AppConfig, TargetConfig, HttpConfig, StealthConfig
from learnwhitehack.core.reporter import Report


@pytest.fixture
def sample_config() -> AppConfig:
    """Configuration de test avec délais désactivés."""
    cfg = AppConfig()
    cfg.target = TargetConfig(url="https://test.example.com", ip="127.0.0.1", name="test")
    cfg.http = HttpConfig(timeout=5, verify_ssl=False)
    cfg.stealth = StealthConfig(min_delay=0.0, max_delay=0.0)
    return cfg


@pytest.fixture
def sample_report() -> Report:
    """Rapport vide pour les tests."""
    return Report(target_url="https://test.example.com", target_ip="127.0.0.1")


@pytest.fixture
def mock_responses():
    """Active le mocking des requêtes HTTP via la librairie responses."""
    with responses_lib.RequestsMock() as rsps:
        yield rsps
