"""Adaptador de OSV-Scanner (dependencias).

Consulta la API de OSV con nombres y versiones de paquetes: solo se ejecuta si
network.allow_external_scanners es true. Sintaxis v2: `osv-scanner scan source -r --format json <dir>`;
si el binario no tiene el subcomando `scan` (v1) se usa `osv-scanner -r --format json <dir>`.
Códigos de salida documentados por la herramienta: 0 limpio, 1 vulnerabilidades, 127 error, 128 sin
paquetes; aquí la salida JSON válida prevalece sobre el código, salvo 127.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from ..catalog import by_id
from ..findings import make_finding
from ..inventory import is_excluded
from ..redact import sanitize_text
from .base import (CLEAN, ERROR, FINDINGS, INVALID, MISSING, NO_PACKAGES, SKIPPED_POLICY, TIMEOUT, ToolAdapter,
                   execute, finish, new_run, norm_rel)

SEV_WORDS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _sev_from_score(score: Any) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else ""


class OsvScanner(ToolAdapter):
    name = "osv-scanner"
    capability = "dependencies"
    env_var = "SC_OSV_BIN"
    version_args = ["--version"]

    def run(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.monotonic()
        run = new_run(self.name, self.capability)
        det = self.detect()
        if not det["available"]:
            run["status"] = MISSING
            run["notes"].append("osv-scanner no está instalado o no está en PATH (no se instala automáticamente).")
            return finish(run, None, t0)
        run["binary"], run["version"] = det["binary"], det["version"]
        if not ctx["network_allowed"]:
            run["status"] = SKIPPED_POLICY
            run["notes"].append(
                "No se ejecutó: network.allow_external_scanners=false. La consulta enviaría a api.osv.dev "
                "ecosistema, nombre y versión de cada paquete (no el código). Habilítelo explícitamente o use "
                "una base offline fuera de este skill.")
            return finish(run, None, t0)
        root: Path = ctx["root"]
        try:
            rc, hout, herr, _ = execute([det["binary"], "scan", "--help"], root, 30)
            help_text = (hout + herr).decode("utf-8", "replace")
            v2 = rc == 0 and "source" in help_text
        except (subprocess.TimeoutExpired, OSError):
            help_text, v2 = "", False
        argv = [det["binary"], "scan", "source"] if v2 else [det["binary"]]
        argv += ["-r", "--format", "json"]
        empty_cfg = ctx["workdir"] / "osv-scanner.empty.toml"
        empty_cfg.write_text("", encoding="utf-8")
        if "--config" in help_text:
            argv += ["--config", str(empty_cfg)]
        elif (root / "osv-scanner.toml").exists():
            run["notes"].append("Existe osv-scanner.toml en el repositorio y esta versión no permite ignorarlo: "
                                "podría suprimir vulnerabilidades.")
        argv.append(str(root))
        run["scope"] = "lockfiles/manifiestos descubiertos recursivamente en el proyecto"
        run["exclusions"] = list(ctx["excludes"])
        run["database"] = {"source": "api.osv.dev (consulta en línea)", "fetched": run["started_at"],
                           "note": "La herramienta no informa la versión de la base; se registra la fecha de consulta."}
        try:
            rc, out, err, _ = execute(argv, root, ctx["timeout"])
        except subprocess.TimeoutExpired:
            run["status"] = TIMEOUT
            run["error"] = f"osv-scanner excedió el timeout de {ctx['timeout']}s"
            return finish(run, argv, t0)
        except OSError as exc:
            run["status"] = ERROR
            run["error"] = sanitize_text(str(exc), 300)
            return finish(run, argv, t0)
        run["exit_code"] = rc
        if rc == 127:
            run["status"] = ERROR
            run["error"] = "osv-scanner terminó con error (127): " + sanitize_text(err.decode("utf-8", "replace"), 300)
            return finish(run, argv, t0)
        try:
            data = json.loads(out.decode("utf-8", "replace"))
            if not isinstance(data, dict):
                raise ValueError("no es un objeto")
        except ValueError:
            if rc == 128:
                run["status"] = NO_PACKAGES
                run["notes"].append("osv-scanner no encontró paquetes/lockfiles para analizar.")
            else:
                run["status"] = INVALID
                run["error"] = "La salida JSON de osv-scanner no se pudo interpretar (código %s)." % rc
            return finish(run, argv, t0)

        mappings = by_id()["SEC-DEPS-001"]["mappings"]
        results = data.get("results") or []
        pkg_count = 0
        for res in results:
            src = norm_rel(_rel((res.get("source") or {}).get("path", ""), root))
            if src and is_excluded(src, ctx["excludes"]):
                continue
            for pkg in res.get("packages") or []:
                pkg_count += 1
                p = pkg.get("package") or {}
                vulns = {v.get("id"): v for v in (pkg.get("vulnerabilities") or []) if isinstance(v, dict)}
                scores = {}
                for g in pkg.get("groups") or []:
                    for gid in g.get("ids") or []:
                        scores[gid] = g.get("max_severity")
                for vid, v in sorted(vulns.items()):
                    sev = _sev_from_score(scores.get(vid)) or SEV_WORDS.get(
                        str((v.get("database_specific") or {}).get("severity", "")).upper(), "")
                    conf_note = "" if sev else " (severidad no informada por la fuente; se asume media)"
                    aliases = [a for a in (v.get("aliases") or []) if isinstance(a, str)][:6]
                    name = f"{p.get('name')}@{p.get('version')}"
                    run["findings"].append(make_finding(
                        "SEC-DEPS-001", f"Dependencia vulnerable: {name} ({vid})", sev or "medium", "high",
                        "scanner", tool="osv-scanner", rule_id=str(vid), file=src or None,
                        description=sanitize_text(str(v.get("summary") or "Vulnerabilidad conocida en OSV"), 500)
                        + conf_note,
                        evidence=f"Ecosistema {p.get('ecosystem')}; identificadores: {', '.join([str(vid)] + aliases)}",
                        risk="Un componente con vulnerabilidad conocida puede ser explotable según su uso.",
                        remediation="Actualizar a una versión corregida (ver el aviso en OSV) o documentar mitigación.",
                        mappings=mappings, extra_key=f"{name}|{vid}"))
        if pkg_count == 0:
            run["status"] = NO_PACKAGES
            run["notes"].append("osv-scanner no reportó paquetes: sin cobertura de dependencias.")
        else:
            run["status"] = FINDINGS if run["findings"] else CLEAN
        run["packages_scanned"] = pkg_count
        return finish(run, argv, t0)


def _rel(path: str, root: Path) -> str:
    p = str(path).replace("\\", "/")
    r = str(root).replace("\\", "/").rstrip("/") + "/"
    return p[len(r):] if p.startswith(r) else p
