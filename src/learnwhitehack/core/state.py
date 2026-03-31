"""Gestion de l'état partagé entre modules — pattern Blackboard / ScanContext."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    """Représente une vulnérabilité découverte par un module."""

    module_source: str
    severity: str
    description: str
    payload_used: Optional[str] = None


class ScanContext(BaseModel):
    """État partagé et persisté entre modules lors d'un run-all ou resume.

    Joue le rôle de « blackboard » : chaque module lit ce dont il a besoin
    et enrichit le contexte avec ses propres découvertes.
    """

    target_url: str
    target_ip: Optional[str] = None
    technologies_detected: set[str] = Field(default_factory=set)
    subdomains_found: list[str] = Field(default_factory=list)
    waf_detected: Optional[str] = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    exposed_files: list[str] = Field(default_factory=list)
    completed_modules: list[str] = Field(default_factory=list)

    def mark_complete(self, module: str) -> None:
        """Marque un module comme terminé (pour la logique de resume)."""
        if module not in self.completed_modules:
            self.completed_modules.append(module)

    def is_complete(self, module: str) -> bool:
        """Vérifie si un module a déjà été exécuté dans cette session."""
        return module in self.completed_modules

    def save_to_disk(self, path: Path) -> None:
        """Persiste le contexte en JSON sur le disque.

        model_dump(mode="json") convertit set[str] en list pour la sérialisation.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.model_dump(mode="json"), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @classmethod
    def load_from_disk(cls, path: Path) -> "ScanContext":
        """Charge un contexte depuis un fichier JSON de session.

        Pydantic V2 accepte une list pour un champ set[str] et la recoerce.
        """
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))

    @staticmethod
    def session_path(output_dir: str, target_url: str) -> Path:
        """Calcule le chemin canonique du fichier session pour une cible donnée."""
        sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", target_url)[:60]
        return Path(output_dir) / f".lwh_session_{sanitized}.json"
