"""Tests du module core/config.py."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from learnwhitehack.core.config import AppConfig, load_config
from learnwhitehack.core.exceptions import ConfigError


def test_load_default_config():
    """La config par défaut se charge sans erreur."""
    cfg = load_config()
    assert isinstance(cfg, AppConfig)
    assert cfg.http.timeout == 10
    assert cfg.stealth.min_delay == 1.0


def test_cli_overrides_target(tmp_path):
    """Les overrides CLI (target_url, ip) prennent le dessus."""
    cfg = load_config(target_url="https://override.com", target_ip="1.2.3.4")
    assert cfg.target.url == "https://override.com"
    assert cfg.target.ip == "1.2.3.4"


def test_env_override(monkeypatch):
    """Les variables d'env LWH_* surchargent les valeurs TOML."""
    monkeypatch.setenv("LWH_TARGET_URL", "https://env-override.com")
    monkeypatch.setenv("LWH_STEALTH_MIN_DELAY", "5.0")
    cfg = load_config()
    assert cfg.target.url == "https://env-override.com"
    assert cfg.stealth.min_delay == 5.0


def test_toml_file(tmp_path):
    """Un fichier TOML utilisateur est bien fusionné."""
    toml_file = tmp_path / "test.toml"
    toml_file.write_text('[target]\nurl = "https://toml-target.com"\n')
    cfg = load_config(config_file=toml_file)
    assert cfg.target.url == "https://toml-target.com"


def test_invalid_toml(tmp_path):
    """Un TOML invalide lève ConfigError."""
    bad_file = tmp_path / "bad.toml"
    bad_file.write_bytes(b"\xff\xfe invalid")
    with pytest.raises(ConfigError):
        load_config(config_file=bad_file)


def test_port_list():
    """ScanConfig.port_list() retourne la bonne plage."""
    cfg = load_config()
    cfg.scan.port_range = "1-10"
    ports = cfg.scan.port_list()
    assert ports == list(range(1, 11))
