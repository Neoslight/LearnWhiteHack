"""Chargement et validation de la configuration.

Priorité : default.toml < fichier TOML utilisateur < variables LWH_* < flags CLI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

from learnwhitehack.core.exceptions import ConfigError

_DEFAULT_CONFIG = Path(__file__).parent.parent.parent.parent / "config" / "default.toml"


class TargetConfig(BaseModel):
    url: str = ""
    ip: str = ""
    name: str = "unnamed"


class HttpConfig(BaseModel):
    timeout: int = 10
    retries: int = 2
    verify_ssl: bool = True


class StealthConfig(BaseModel):
    min_delay: float = 1.0
    max_delay: float = 3.5
    ua_pool: str = "builtin"
    proxies: list[str] = Field(default_factory=list)
    respect_robots: bool = False

    @field_validator("max_delay")
    @classmethod
    def max_gte_min(cls, v: float, info: Any) -> float:
        # Si max < min (ex: LWH_STEALTH_MIN_DELAY surchargé sans max), aligner sur min
        if "min_delay" in info.data and v < info.data["min_delay"]:
            return info.data["min_delay"]
        return v


class OutputConfig(BaseModel):
    dir: str = "reports"
    format: str = "json"
    pretty: bool = True


class ScanConfig(BaseModel):
    port_range: str = "1-1024"
    threads: int = 50
    banner_timeout: int = 3

    def port_list(self) -> list[int]:
        """Retourne la liste des ports à scanner."""
        start, end = self.port_range.split("-")
        return list(range(int(start), int(end) + 1))


class NvdConfig(BaseModel):
    api_key: str = ""
    max_results: int = 20


class ShodanConfig(BaseModel):
    api_key: str = ""


class AppConfig(BaseModel):
    target: TargetConfig = Field(default_factory=TargetConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    nvd: NvdConfig = Field(default_factory=NvdConfig)
    shodan: ShodanConfig = Field(default_factory=ShodanConfig)


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        raise ConfigError(f"Impossible de lire {path}: {e}") from e


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Applique les variables d'env LWH_SECTION_KEY sur le dict de config."""
    mapping = {
        "LWH_TARGET_URL": ("target", "url"),
        "LWH_TARGET_IP": ("target", "ip"),
        "LWH_TARGET_NAME": ("target", "name"),
        "LWH_HTTP_TIMEOUT": ("http", "timeout"),
        "LWH_HTTP_RETRIES": ("http", "retries"),
        "LWH_HTTP_VERIFY_SSL": ("http", "verify_ssl"),
        "LWH_STEALTH_MIN_DELAY": ("stealth", "min_delay"),
        "LWH_STEALTH_MAX_DELAY": ("stealth", "max_delay"),
        "LWH_STEALTH_UA_POOL": ("stealth", "ua_pool"),
        "LWH_STEALTH_PROXIES": ("stealth", "proxies"),
        "LWH_OUTPUT_DIR": ("output", "dir"),
        "LWH_OUTPUT_FORMAT": ("output", "format"),
        "LWH_SCAN_PORT_RANGE": ("scan", "port_range"),
        "LWH_SCAN_THREADS": ("scan", "threads"),
        "LWH_NVD_API_KEY": ("nvd", "api_key"),
        "LWH_NVD_MAX_RESULTS": ("nvd", "max_results"),
        "LWH_SHODAN_API_KEY": ("shodan", "api_key"),
    }
    result = data.copy()
    for env_key, (section, field) in mapping.items():
        val = os.environ.get(env_key)
        if val is None:
            continue
        if section not in result:
            result[section] = {}
        # Conversion de types simples
        if field in ("min_delay", "max_delay"):
            result[section][field] = float(val)
        elif field in ("timeout", "retries", "threads", "max_results"):
            result[section][field] = int(val)
        elif field == "verify_ssl":
            result[section][field] = val.lower() not in ("false", "0", "no")
        elif field == "proxies":
            result[section][field] = [v.strip() for v in val.split(",") if v.strip()]
        else:
            result[section][field] = val
    return result


def load_config(
    config_file: Path | None = None,
    *,
    target_url: str | None = None,
    target_ip: str | None = None,
    output_dir: str | None = None,
) -> AppConfig:
    """Charge la config en fusionnant : defaults < fichier < env < args CLI."""
    data: dict[str, Any] = _load_toml(_DEFAULT_CONFIG)
    if config_file:
        data = _deep_merge(data, _load_toml(config_file))
    data = _apply_env_overrides(data)
    # Overrides CLI directs
    if target_url:
        data.setdefault("target", {})["url"] = target_url
    if target_ip:
        data.setdefault("target", {})["ip"] = target_ip
    if output_dir:
        data.setdefault("output", {})["dir"] = output_dir
    try:
        return AppConfig.model_validate(data)
    except Exception as e:
        raise ConfigError(f"Configuration invalide: {e}") from e
