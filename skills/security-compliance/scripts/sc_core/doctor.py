"""Diagnóstico de instalación, runtime, scanners, configuración y capacidades. No instala nada."""
from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any, Dict, List

from . import SKILL_ROOT, clients, config as cfgmod, gitutil, skill_version, skillcheck
from .errors import ConfigError
from .tools.gitleaks import Gitleaks
from .tools.osv import OsvScanner
from .tools.semgrep import Semgrep

MIN_PYTHON = (3, 9)


def run_doctor(project: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    def add(name: str, status: str, detail: str, fix: str = "") -> None:
        checks.append({"name": name, "status": status, "detail": detail, "fix": fix})

    py_ok = sys.version_info[:2] >= MIN_PYTHON
    add("python", "ok" if py_ok else "error",
        f"{platform.python_version()} ({sys.executable})",
        "" if py_ok else f"Se requiere Python >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]} (no se instala automáticamente).")
    add("skill_version", "ok", f"{skill_version()} en {SKILL_ROOT}")

    pkg = skillcheck.validate_package(SKILL_ROOT)
    add("package", "ok" if pkg["ok"] else "error",
        "frontmatter, archivos requeridos y referencias internas válidos" if pkg["ok"] else "; ".join(pkg["errors"][:6]),
        "" if pkg["ok"] else "Reinstale el skill (install --update) o restaure los archivos faltantes.")
    marker = skillcheck.check_marker(SKILL_ROOT)
    if not marker["installed"]:
        add("install_files", "info", marker["reason"])
    elif marker.get("intact"):
        add("install_files", "ok", f"archivos instalados correctamente (v{marker['version']}, cliente {marker['client']}, "
            f"alcance {marker['scope']}, invocación {marker['invocation']})")
    else:
        add("install_files", "warn", "archivos modificados o faltantes: " + ", ".join((marker.get("modified") or []) + (marker.get("missing") or []))
            if marker.get("modified") or marker.get("missing") else marker.get("reason", ""),
            "Use install --update --force para restaurar (se crea un respaldo).")
    add("client_discovery", "unverified",
        "No comprobado dentro del cliente: 'archivos instalados' no prueba que el cliente descubra el skill.",
        "En el cliente, escriba /security-compliance help (o pida usar el skill) y confirme que responde.")

    git_ok = gitutil.git_available()
    add("git", "ok" if git_ok else "warn", "disponible" if git_ok else "no encontrado",
        "" if git_ok else "Sin git: solo audit sobre archivos, trazabilidad parcial.")

    for ad in (Semgrep(), Gitleaks(), OsvScanner()):
        d = ad.detect()
        add(f"scanner:{ad.name}", "ok" if d["available"] else "missing",
            f"{d['version'] or 'versión desconocida'} ({d['binary']})" if d["available"] else "no instalado",
            "" if d["available"] else f"Instale {ad.name} con su gestor habitual si desea la capacidad '{ad.capability}'; el skill no lo instala.")

    cfg_file = project / cfgmod.CONFIG_NAME
    cfg_info: Dict[str, Any] = {"found": cfg_file.is_file()}
    network = False
    if cfg_file.is_file():
        try:
            cfg, meta = cfgmod.load_effective(project)
            add("project_config", "ok", f"{cfgmod.CONFIG_NAME} válido ({meta['config_hash'][:19]}…)")
            network = cfg["network"]["allow_external_scanners"]
        except ConfigError as exc:
            add("project_config", "error", str(exc).splitlines()[0], "Corrija la configuración (ver assets/config.example.yml).")
    else:
        add("project_config", "info", f"sin {cfgmod.CONFIG_NAME}: la revisión exploratoria usa valores por defecto",
            "Ejecute 'init' para generar una configuración mínima (opcional).")
    add("network_policy", "ok", "scanners externos " + ("PERMITIDOS" if network else "no permitidos (por defecto)")
        + ": la consulta de vulnerabilidades (OSV) solo se ejecuta si se permite explícitamente.")

    home = Path.home()
    inst = clients.find_installs(home, project)
    if len(inst) > 1:
        add("duplicates", "warn", f"{len(inst)} instalaciones detectadas: " + "; ".join(f"{i['skill_dir']}" for i in inst),
            "Conserve una sola. " + " ".join(clients.PRECEDENCE_NOTES.values()) + " (el instalador no borra nada automáticamente).")
    else:
        add("duplicates", "ok", f"{len(inst)} instalación detectada en rutas de descubrimiento conocidas")

    avail = {ad.capability: ad.detect()["available"] for ad in (Semgrep(), Gitleaks(), OsvScanner())}
    caps = {
        "assisted_review": True,
        "evidence_import": True,
        "report_generation": True,
        "sast_scanner": avail["sast"],
        "secrets_scanner": avail["secrets"],
        "dependency_scanner": avail["dependencies"] and network,
        "git_diff": git_ok and gitutil.is_git_repo(project),
    }
    worst = "error" if any(c["status"] == "error" for c in checks) else (
        "warn" if any(c["status"] in ("warn", "missing") for c in checks) else "ok")
    return {"overall": worst, "skill_version": skill_version(), "python": platform.python_version(),
            "platform": platform.platform(), "checks": checks, "capabilities": caps,
            "exit_code": 2 if worst == "error" else 0, "config": cfg_info}


def format_doctor(r: Dict[str, Any]) -> str:
    icon = {"ok": "✓", "info": "·", "warn": "!", "missing": "–", "error": "✗", "unverified": "?"}
    lines = [f"security-compliance doctor — v{r['skill_version']} — Python {r['python']} — {r['platform']}", ""]
    for c in r["checks"]:
        lines.append(f"  [{icon.get(c['status'], '·')}] {c['name']}: {c['detail']}")
        if c["fix"]:
            lines.append(f"        → {c['fix']}")
    lines += ["", "Capacidades disponibles ahora:"]
    for k, v in r["capabilities"].items():
        lines.append(f"  - {k}: {'sí' if v else 'no'}")
    lines += ["", f"Resultado: {r['overall'].upper()}  (✓ ok · ! advertencia · – ausente · ? no comprobado · ✗ error)"]
    return "\n".join(lines)
