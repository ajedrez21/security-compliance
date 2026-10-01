"""Rutas de descubrimiento/instalación por cliente (verificadas contra la documentación oficial; ver docs/COMPATIBILITY.md)."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

SKILL_NAME = "security-compliance"
CLIENTS = ("cursor", "claude", "codex")


def install_target(client: str, scope: str, home: Path, project: Optional[Path]) -> Path:
    """Directorio base de skills donde se instala el skill para (cliente, alcance)."""
    if scope == "project":
        if project is None:
            raise ValueError("scope=project requiere project_path")
        base = project
    else:
        base = home
    sub = {"cursor": ".cursor/skills", "claude": ".claude/skills", "codex": ".agents/skills"}[client]
    return base / sub


def discovery_dirs(home: Path, project: Optional[Path]) -> List[Dict[str, str]]:
    """Todos los directorios donde algún cliente soportado puede descubrir el skill."""
    out: List[Dict[str, str]] = []
    glob = [(".cursor/skills", "cursor"), (".agents/skills", "cursor, codex"), (".claude/skills", "claude (y compat. cursor)"),
            (".codex/skills", "compat. cursor (legado)")]
    for sub, who in glob:
        out.append({"scope": "global", "clients": who, "path": str(home / sub)})
        if project is not None:
            out.append({"scope": "project", "clients": who, "path": str(project / sub)})
    return out


PRECEDENCE_NOTES = {
    "claude": "Claude Code: ante el mismo nombre gana Enterprise > Personal (~/.claude/skills) > Proyecto (.claude/skills).",
    "cursor": "Cursor: lee .agents/skills, .cursor/skills y, por compatibilidad, .claude/skills y .codex/skills; la "
              "documentación consultada no define la precedencia entre duplicados.",
    "codex": "Codex: los skills homónimos de distintos alcances NO se fusionan; aparecen ambos en los selectores.",
}


def find_installs(home: Path, project: Optional[Path]) -> List[Dict[str, object]]:
    found = []
    for d in discovery_dirs(home, project):
        p = Path(d["path"]) / SKILL_NAME
        if (p / "SKILL.md").is_file():
            found.append({**d, "skill_dir": str(p), "marker": (p / ".sc-install.json").is_file()})
    return found
