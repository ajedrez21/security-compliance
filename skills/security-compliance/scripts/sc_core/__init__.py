"""Núcleo determinístico del skill security-compliance (solo biblioteca estándar)."""
from __future__ import annotations

from pathlib import Path

# scripts/sc_core/__init__.py -> raíz del skill (dos niveles arriba de scripts/)
SKILL_ROOT = Path(__file__).resolve().parent.parent.parent


def skill_version() -> str:
    try:
        return (SKILL_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
