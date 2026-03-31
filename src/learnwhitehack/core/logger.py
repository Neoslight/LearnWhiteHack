"""Configuration du logging structuré.

- Console : Rich, coloré, niveau INFO par défaut (DEBUG si --verbose)
- Fichier : JSON lines dans reports/learnwhitehack.log, toujours DEBUG
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

# Console partagée — utilisée par le CLI et le reporter pour une sortie cohérente
console = Console()


def setup_logging(verbose: bool = False, log_dir: str = "reports") -> logging.Logger:
    """Configure et retourne le logger racine du toolkit."""
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("learnwhitehack")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        logger.handlers.clear()

    # Handler console (Rich)
    console_handler = RichHandler(
        level=level,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
    )
    console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    logger.addHandler(console_handler)

    # Handler fichier (JSON lines)
    try:
        log_path = Path(log_dir) / "learnwhitehack.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                '{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":%(message)r}'
            )
        )
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Impossible d'ouvrir le fichier de log.")

    return logger


def get_logger(name: str) -> logging.Logger:
    """Retourne un logger enfant du logger racine."""
    return logging.getLogger(f"learnwhitehack.{name}")
