"""Interfaz común de adaptadores de herramientas + ejecución controlada.

Estados de una ejecución (ToolRun.status):
  clean            ejecutó bien y sin hallazgos
  findings         ejecutó bien y reportó hallazgos (no es un error técnico)
  no_packages      la herramienta no encontró nada que analizar (sin cobertura; NO es 'clean')
  missing          el binario no está disponible
  skipped_policy   no se ejecutó por política (p. ej. red no permitida)
  timeout          excedió el tiempo
  invalid_output   salida no interpretable
  error            falla técnica (código de salida inesperado, flag no soportado, etc.)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..redact import sanitize_command, sanitize_text

CLEAN, FINDINGS, NO_PACKAGES, MISSING = "clean", "findings", "no_packages", "missing"
SKIPPED_POLICY, TIMEOUT, INVALID, ERROR = "skipped_policy", "timeout", "invalid_output", "error"
COMPLETED = (CLEAN, FINDINGS)


def norm_rel(path: str) -> str:
    """Normaliza una ruta relativa de scanner ('./a/b' → 'a/b') sin comerse puntos iniciales legítimos."""
    p = str(path).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run(tool: str, capability: str) -> Dict[str, Any]:
    return {"tool": tool, "capability": capability, "status": ERROR, "version": None, "binary": None,
            "started_at": utcnow(), "duration_seconds": 0.0, "command": "", "exit_code": None,
            "scope": "", "findings": [], "notes": [], "error": None, "rules": None,
            "exclusions": [], "database": None}


def resolve_binary(name: str, env_var: str) -> Optional[str]:
    """Precedencia: variable de entorno SC_<TOOL>_BIN (ruta explícita del usuario) → PATH.

    Nunca se resuelven binarios dentro del proyecto auditado (el repositorio no es confiable).
    """
    explicit = os.environ.get(env_var)
    if explicit:
        p = shutil.which(explicit) or (explicit if os.path.isfile(explicit) and os.access(explicit, os.X_OK) else None)
        return p
    return shutil.which(name)


def tool_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    keep = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "XDG_CACHE_HOME",
            "LOCALAPPDATA", "APPDATA")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update(extra or {})
    return env


def execute(argv: List[str], cwd: Path, timeout: int, extra_env: Optional[Dict[str, str]] = None):
    """subprocess sin shell. Devuelve (returncode, stdout, stderr, duration) o lanza TimeoutExpired."""
    t0 = time.monotonic()
    p = subprocess.run(argv, cwd=str(cwd), capture_output=True, timeout=timeout, shell=False,
                       env=tool_env(extra_env))
    return p.returncode, p.stdout, p.stderr, time.monotonic() - t0


def probe_version(binary: str, args: List[str], timeout: int = 20) -> Optional[str]:
    try:
        p = subprocess.run([binary, *args], capture_output=True, timeout=timeout, shell=False, env=tool_env())
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = (p.stdout or p.stderr).decode("utf-8", "replace").strip().splitlines()
    return sanitize_text(text[0], 120) if text else None


def finish(run: Dict[str, Any], argv: Optional[List[str]], t0: float) -> Dict[str, Any]:
    if argv:
        run["command"] = sanitize_command(argv)
    run["duration_seconds"] = round(time.monotonic() - t0, 3)
    return run


class ToolAdapter:
    """Contrato: detect() → ruta/versión; run() → ToolRun normalizado."""

    name = ""
    capability = ""
    env_var = ""
    version_args = ["--version"]

    def detect(self) -> Dict[str, Any]:
        binary = resolve_binary(self.name, self.env_var)
        if not binary:
            return {"available": False, "binary": None, "version": None}
        return {"available": True, "binary": binary, "version": probe_version(binary, self.version_args)}

    def run(self, ctx: Dict[str, Any]) -> Dict[str, Any]:  # pragma: no cover - interfaz
        raise NotImplementedError
