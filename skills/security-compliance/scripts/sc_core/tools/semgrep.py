"""Adaptador de Semgrep (SAST) con reglas locales versionadas dentro del skill.

No se usan reglas del registro ni de la configuración del repositorio: la ejecución es reproducible
y funciona sin red. Comando:
  semgrep scan --config <rulesets/semgrep-local.yml> --json --metrics=off --disable-version-check
         --quiet --exclude <paths.exclude>... [--x-ignore-semgrepignore-files] <rutas>
Códigos de salida: 0 ejecución correcta (con o sin hallazgos, porque no se usa --error); 1 se tolera
solo si la salida es JSON; cualquier otro código es error técnico.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from .. import SKILL_ROOT
from ..catalog import by_id
from ..findings import make_finding
from ..redact import sanitize_text
from .base import (CLEAN, ERROR, FINDINGS, INVALID, MISSING, NO_PACKAGES, TIMEOUT, ToolAdapter, execute, finish,
                   new_run, norm_rel)

RULES_FILE = SKILL_ROOT / "rulesets" / "semgrep-local.yml"
SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
MAX_PATH_ARGS = 400


def _rule_id(check_id) -> str:
    """Semgrep antepone la ruta de la config al id (p. ej. 'Users.x.rulesets.sc.python.eval'); se deja solo 'sc.…'."""
    cid = str(check_id or "")
    i = cid.find("sc.")
    return cid[i:] if i > 0 else cid


class Semgrep(ToolAdapter):
    name = "semgrep"
    capability = "sast"
    env_var = "SC_SEMGREP_BIN"
    version_args = ["--version"]

    def run(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.monotonic()
        run = new_run(self.name, self.capability)
        det = self.detect()
        if not det["available"]:
            run["status"] = MISSING
            run["notes"].append("semgrep no está instalado o no está en PATH (no se instala automáticamente).")
            return finish(run, None, t0)
        run["binary"], run["version"] = det["binary"], det["version"]
        if not RULES_FILE.is_file():
            run["status"] = ERROR
            run["error"] = "Faltan las reglas locales incluidas en el skill (rulesets/semgrep-local.yml)."
            return finish(run, None, t0)
        run["rules"] = {"source": "bundled", "file": "rulesets/semgrep-local.yml",
                        "sha256": hashlib.sha256(RULES_FILE.read_bytes()).hexdigest(),
                        "registry_used": False, "repo_rules_used": False}
        root: Path = ctx["root"]

        targets = ["."]
        changed = ctx.get("changed_paths")
        if changed is not None:
            existing = sorted(p for p in changed if (root / p).is_file())
            if not existing:
                run["status"] = NO_PACKAGES
                run["scope"] = "sin archivos cambiados existentes para analizar"
                run["notes"].append("No hay archivos modificados analizables; no se hizo análisis.")
                return finish(run, None, t0)
            if len(existing) <= MAX_PATH_ARGS:
                targets = existing
                run["scope"] = f"{len(existing)} archivos cambiados"
            else:
                run["scope"] = "proyecto completo (demasiados archivos cambiados para pasarlos uno a uno)"
                run["notes"].append("Semgrep analizó todo el proyecto; los hallazgos fuera del diff se marcan fuera de alcance.")
        else:
            run["scope"] = "proyecto completo"

        argv = [det["binary"], "scan", "--config", str(RULES_FILE), "--json", "--metrics=off",
                "--disable-version-check", "--quiet"]
        for ex in ctx["excludes"]:
            argv += ["--exclude", ex]
        try:
            _, hout, herr, _ = execute([det["binary"], "scan", "--help"], root, 30)
            help_text = (hout + herr).decode("utf-8", "replace")
        except (subprocess.TimeoutExpired, OSError):
            help_text = ""
        if "--x-ignore-semgrepignore-files" in help_text:
            argv.append("--x-ignore-semgrepignore-files")
        else:
            run["notes"].append("No se pudo desactivar .semgrepignore del repositorio en esta versión.")
        argv += ["./" + t if t != "." else t for t in targets]  # "./" evita que un nombre con "-" se lea como flag
        run["exclusions"] = list(ctx["excludes"])
        env = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
        try:
            rc, out, err, _ = execute(argv, root, ctx["timeout"], env)
        except subprocess.TimeoutExpired:
            run["status"] = TIMEOUT
            run["error"] = f"semgrep excedió el timeout de {ctx['timeout']}s"
            return finish(run, argv, t0)
        except OSError as exc:
            run["status"] = ERROR
            run["error"] = sanitize_text(str(exc), 300)
            return finish(run, argv, t0)
        run["exit_code"] = rc
        if rc not in (0, 1):
            run["status"] = ERROR
            run["error"] = f"semgrep terminó con código {rc}: " + sanitize_text(err.decode("utf-8", "replace"), 300)
            return finish(run, argv, t0)
        try:
            data = json.loads(out.decode("utf-8", "replace"))
            if not isinstance(data, dict) or "results" not in data:
                raise ValueError("JSON sin 'results'")
        except ValueError:
            run["status"] = INVALID
            run["error"] = "La salida JSON de semgrep no se pudo interpretar."
            return finish(run, argv, t0)

        errors = data.get("errors") or []
        run["partial"] = bool(errors)
        if errors:
            run["notes"].append(f"semgrep reportó {len(errors)} errores de análisis: cobertura parcial.")
        mappings = by_id()["SEC-SAST-001"]["mappings"]
        for r in data["results"]:
            if not isinstance(r, dict):
                continue
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}
            cwe = meta.get("cwe")
            cwe_s = ", ".join(cwe) if isinstance(cwe, list) else (str(cwe) if cwe else "")
            conf = str(meta.get("confidence") or "medium").lower()
            run["findings"].append(make_finding(
                "SEC-SAST-001", sanitize_text(str(extra.get("message") or r.get("check_id") or "Hallazgo SAST"), 200),
                SEV.get(str(extra.get("severity", "")).upper(), "medium"),
                conf if conf in ("high", "medium", "low") else "medium", "scanner",
                tool="semgrep", rule_id=_rule_id(r.get("check_id")), file=norm_rel(str(r.get("path") or "")),
                start_line=(r.get("start") or {}).get("line"), end_line=(r.get("end") or {}).get("line"),
                description=sanitize_text(str(extra.get("message") or ""), 600),
                evidence=("Regla " + _rule_id(r.get("check_id")) + (f"; {cwe_s}" if cwe_s else "")),
                risk="Patrón de código asociado a una vulnerabilidad; requiere validar el flujo de datos.",
                remediation="Revisar el hallazgo, corregir el patrón inseguro o documentar una excepción justificada.",
                mappings=mappings))
        run["status"] = FINDINGS if run["findings"] else CLEAN
        return finish(run, argv, t0)
