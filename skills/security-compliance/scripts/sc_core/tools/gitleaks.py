"""Adaptador de Gitleaks (secretos). Nunca persiste Match/Secret/Line: solo regla, archivo y línea.

Comando (Gitleaks >= 8.19, subcomando 'dir'):
  gitleaks dir <root> --config <toml propio> --report-format json --report-path <tmp> --redact
         --no-banner --exit-code 2 [--gitleaks-ignore-path <vacío>]
Con --exit-code 2 se distingue "hay hallazgos" (2) de error técnico (1, por defecto de gitleaks).
La configuración propia (extend useDefault + allowlist de exclusiones) evita usar .gitleaks.toml
del repositorio.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

from ..catalog import by_id
from ..findings import make_finding
from ..redact import sanitize_text
from .base import (CLEAN, ERROR, FINDINGS, INVALID, MISSING, TIMEOUT, ToolAdapter, execute, finish, new_run,
                   norm_rel)


def _toml_regex(pattern: str) -> str:
    p = pattern.replace("\\", "/").strip("/")
    rx = re.escape(p).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
    return f"(^|/){rx}($|/)"


def build_config(excludes: List[str]) -> str:
    lines = ['title = "security-compliance (config propia)"', "", "[extend]", "useDefault = true", "",
             "[allowlist]", 'description = "exclusiones del alcance (paths.exclude)"', "paths = ["]
    for ex in excludes:
        lines.append("  '''" + _toml_regex(ex).replace("'''", "") + "''',")
    lines.append("]")
    return "\n".join(lines) + "\n"


def _version_tuple(text: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


class Gitleaks(ToolAdapter):
    name = "gitleaks"
    capability = "secrets"
    env_var = "SC_GITLEAKS_BIN"
    version_args = ["version"]

    def run(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.monotonic()
        run = new_run(self.name, self.capability)
        det = self.detect()
        if not det["available"]:
            run["status"] = MISSING
            run["notes"].append("gitleaks no está instalado o no está en PATH (no se instala automáticamente).")
            return finish(run, None, t0)
        run["binary"], run["version"] = det["binary"], det["version"]
        ver = _version_tuple(det["version"] or "")
        if ver and ver < (8, 19, 0):
            run["status"] = ERROR
            run["error"] = f"Gitleaks {det['version']} no soporta el subcomando 'dir' (se requiere >= 8.19)."
            return finish(run, None, t0)

        root: Path = ctx["root"]
        work: Path = ctx["workdir"]
        cfg_path, report, ignore_path = work / "gitleaks.toml", work / "gitleaks-report.json", work / "gitleaksignore.empty"
        cfg_path.write_text(build_config(ctx["excludes"]), encoding="utf-8")
        ignore_path.write_text("", encoding="utf-8")
        run["exclusions"] = list(ctx["excludes"])
        run["rules"] = {"source": "gitleaks default ruleset (extend useDefault) + allowlist propia",
                        "repo_config_used": False}

        try:
            help_rc, help_out, help_err, _ = execute([det["binary"], "dir", "--help"], root, 30)
            help_text = (help_out + help_err).decode("utf-8", "replace")
        except (subprocess.TimeoutExpired, OSError):
            help_text = ""
        argv = [det["binary"], "dir", str(root), "--config", str(cfg_path), "--report-format", "json",
                "--report-path", str(report), "--redact", "--no-banner", "--exit-code", "2"]
        if "--gitleaks-ignore-path" in help_text:
            argv += ["--gitleaks-ignore-path", str(ignore_path)]
        else:
            run["notes"].append("Esta versión no expone --gitleaks-ignore-path: un .gitleaksignore del "
                                "repositorio podría suprimir hallazgos.")
        run["scope"] = "directorio completo del proyecto (gitleaks dir) con paths.exclude como allowlist"
        try:
            rc, out, err, _ = execute(argv, root, ctx["timeout"])
        except subprocess.TimeoutExpired:
            run["status"] = TIMEOUT
            run["error"] = f"gitleaks excedió el timeout de {ctx['timeout']}s"
            return finish(run, argv, t0)
        except OSError as exc:
            run["status"] = ERROR
            run["error"] = sanitize_text(str(exc), 300)
            return finish(run, argv, t0)
        run["exit_code"] = rc
        if rc not in (0, 2):
            run["status"] = ERROR
            run["error"] = f"gitleaks terminó con código {rc}: " + sanitize_text(err.decode("utf-8", "replace"), 300)
            return finish(run, argv, t0)
        try:
            data = json.loads(report.read_text(encoding="utf-8")) if report.exists() else []
            if not isinstance(data, list):
                raise ValueError("el reporte no es una lista")
        except (ValueError, OSError):
            run["status"] = INVALID
            run["error"] = "El reporte JSON de gitleaks no se pudo interpretar."
            return finish(run, argv, t0)
        finally:
            try:  # el reporte crudo nunca se conserva
                report.unlink()
            except OSError:
                pass

        mappings = by_id()["SEC-SECRETS-001"]["mappings"]
        for item in data:
            if not isinstance(item, dict):
                continue
            rule = str(item.get("RuleID") or "unknown-rule")
            rel = _relpath(str(item.get("File") or ""), root)
            generic = "generic" in rule
            run["findings"].append(make_finding(
                "SEC-SECRETS-001", f"Posible secreto detectado ({rule})",
                "medium" if generic else "high", "low" if generic else "medium", "scanner",
                tool="gitleaks", rule_id=rule, file=rel, start_line=_int(item.get("StartLine")),
                end_line=_int(item.get("EndLine")),
                description=sanitize_text(str(item.get("Description") or "Credencial potencial detectada"), 300),
                evidence="Valor redactado; no se conserva el secreto ni su línea.",
                risk="Una credencial expuesta en el código permite acceso no autorizado y queda en el historial.",
                remediation="Rotar la credencial, retirarla del código y gestionarla en un gestor de secretos; "
                            "evaluar su presencia en el historial Git.",
                mappings=mappings, extra_key=str(item.get("Fingerprint") or "")))
        run["status"] = FINDINGS if run["findings"] else CLEAN
        return finish(run, argv, t0)


def _int(v: Any):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _relpath(file: str, root: Path) -> str:
    p = file.replace("\\", "/")
    r = str(root).replace("\\", "/").rstrip("/") + "/"
    return norm_rel(p[len(r):] if p.startswith(r) else p)
