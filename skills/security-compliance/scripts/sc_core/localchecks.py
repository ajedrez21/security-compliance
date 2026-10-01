"""Comprobaciones locales determinísticas y heurísticas (no son scanners).

* heurística de secretos: aporta candidatos (origin='heuristic'); nunca guarda el valor.
* lockfiles, Dockerfile sin USER no root, imágenes base sin versión fija (origin='local_observation').
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .catalog import by_id
from .findings import make_finding

# (id, regex, severidad, confianza, descripción)
SECRET_PATTERNS: List[Tuple[str, "re.Pattern", str, str, str]] = [
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
     "high", "medium", "Bloque de clave privada"),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high", "medium", "Posible AWS access key id"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "high", "medium", "Posible token de GitHub"),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), "high", "medium", "Posible token de Slack"),
    ("hardcoded-credential-assignment",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|access[_-]?token)\b\s*[:=]\s*"
                r"[\"'][^\"'\s]{12,}[\"']"), "low", "low",
     "Asignación literal a una variable con nombre de credencial (heurística débil)"),
]
_PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[_-]|<[^>]+>|\$\{|process\.env|os\.environ|getenv|"
                          r"xxxx|\*\*\*\*|dummy)")
TEXT_EXT_SKIP = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".jar", ".woff", ".woff2",
                 ".lock", ".min.js", ".map")


def heuristic_secret_candidates(root: Path, files: List[Dict[str, Any]], changed: set = None) -> List[Dict[str, Any]]:
    mappings = by_id()["SEC-SECRETS-001"]["mappings"]
    out: List[Dict[str, Any]] = []
    for e in files:
        if e.get("skipped") or e.get("binary") or e["size"] > 1_000_000:
            continue
        rel = e["path"]
        if rel.lower().endswith(TEXT_EXT_SKIP):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                continue
            for rid, rx, sev, conf, desc in SECRET_PATTERNS:
                if rx.search(line) and not (rid == "hardcoded-credential-assignment" and _PLACEHOLDER.search(line)):
                    out.append(make_finding(
                        "SEC-SECRETS-001", f"Candidato a secreto ({rid})", sev, conf, "heuristic",
                        tool="sc-heuristics", rule_id=rid, file=rel, start_line=lineno,
                        description=desc + ". Coincidencia por expresión regular; requiere confirmación.",
                        evidence="Valor no almacenado.",
                        risk="Si es una credencial real, expone acceso no autorizado.",
                        remediation="Confirmar con un scanner de secretos; si es real, rotar y retirar del código.",
                        mappings=mappings, in_scope=(changed is None or rel in changed)))
                    break
            if len(out) > 500:
                return out
    return out


def count_inline_suppressions(root: Path, files: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"gitleaks:allow": 0, "nosemgrep": 0}
    for e in files:
        if e.get("skipped") or e.get("binary") or e["size"] > 500_000:
            continue
        try:
            text = (root / e["path"]).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for key in counts:
            counts[key] += text.count(key)
    return {k: v for k, v in counts.items() if v}


# ------------------------------------------------------------------ lockfiles

def check_lockfiles(inv_deps: Dict[str, Any], changed: set = None) -> Dict[str, Any]:
    ctrl = by_id()["SEC-DEPS-002"]
    manifests = inv_deps["manifests"]
    evaluable = [m for m in manifests if m["lock_expected"]]
    findings, missing = [], []
    for m in evaluable:
        if not m["lockfile"]:
            missing.append(m["file"])
            findings.append(make_finding(
                "SEC-DEPS-002", f"Manifiesto sin lockfile: {m['file']}", "low", "high", "local_observation",
                tool="sc-local", rule_id="missing-lockfile", file=m["file"],
                description="No se encontró un lockfile junto al manifiesto (" + ", ".join(m["lock_candidates"]) + ").",
                evidence="Archivo de bloqueo ausente en el alcance.",
                risk="Sin versiones resueltas fijas, las instalaciones no son reproducibles ni auditables.",
                remediation="Generar y versionar el lockfile del gestor de paquetes.",
                mappings=ctrl["mappings"], in_scope=(changed is None or m["file"] in changed)))
    if not manifests:
        status, reason = "NOT_APPLICABLE", "No se detectaron manifiestos de dependencias en el alcance."
    elif not evaluable:
        status, reason = "UNKNOWN", "Los manifiestos detectados (p. ej. Maven) no tienen un lockfile estándar evaluable."
    elif missing:
        status, reason = "FAIL", f"{len(missing)} manifiesto(s) sin lockfile."
    else:
        status, reason = "PASS", f"{len(evaluable)} manifiesto(s) con lockfile."
    return {"status": status, "reason": reason, "findings": findings}


# ------------------------------------------------------------------ Dockerfile

def _docker_instructions(text: str) -> List[Tuple[int, str, str]]:
    out: List[Tuple[int, str, str]] = []
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        parts = buf.split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buf = ""
    return out


def check_dockerfiles(root: Path, files: List[Dict[str, Any]], changed: set = None) -> Dict[str, Dict[str, Any]]:
    results = {"SEC-INFRA-001": {"findings": [], "checked": 0, "unknown": 0},
               "SEC-INFRA-002": {"findings": [], "checked": 0, "unknown": 0}}
    for e in files:
        base = e["path"].rsplit("/", 1)[-1].lower()
        if not (base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile")):
            continue
        if e.get("skipped") or e.get("binary"):
            continue
        rel = e["path"]
        ins = _docker_instructions((root / rel).read_text(encoding="utf-8", errors="replace"))
        in_scope = changed is None or rel in changed
        stages: List[Dict[str, Any]] = []
        aliases = set()
        for line, op, arg in ins:
            if op == "FROM":
                toks = [t for t in arg.split() if not t.startswith("--")]
                image = toks[0] if toks else ""
                if len(toks) >= 3 and toks[1].upper() == "AS":
                    alias = toks[2].lower()
                else:
                    alias = ""
                stages.append({"image": image, "line": line, "user": None, "user_line": None})
                _pin_check(results["SEC-INFRA-002"], rel, line, image, aliases, in_scope)
                if alias:
                    aliases.add(alias)
            elif op == "USER" and stages:
                stages[-1]["user"], stages[-1]["user_line"] = arg.split()[0] if arg.split() else "", line
        results["SEC-INFRA-001"]["checked"] += 1
        if not stages:
            results["SEC-INFRA-001"]["unknown"] += 1
            continue
        last = stages[-1]
        user = (last["user"] or "").strip("\"'")
        ctrl = by_id()["SEC-INFRA-001"]
        if user.startswith("$"):
            results["SEC-INFRA-001"]["unknown"] += 1
        elif user == "" or user.split(":")[0].lower() in ("root", "0"):
            results["SEC-INFRA-001"]["findings"].append(make_finding(
                "SEC-INFRA-001", f"Contenedor ejecuta como root: {rel}", "medium", "high", "local_observation",
                tool="sc-local", rule_id="docker-user-root", file=rel, start_line=last["user_line"] or last["line"],
                description=("El último stage no define USER" if not user else f"El último stage usa USER {user}")
                + "; el proceso corre como root.",
                evidence="Instrucción USER ausente o root en el último stage.",
                risk="Un compromiso del proceso tiene privilegios de root dentro del contenedor.",
                remediation="Crear y usar un usuario sin privilegios (USER app) en la imagen final.",
                mappings=ctrl["mappings"], in_scope=in_scope))
    return results


def _pin_check(res: Dict[str, Any], rel: str, line: int, image: str, aliases: set, in_scope: bool) -> None:
    res["checked"] += 1
    low = image.lower()
    if not image or low == "scratch" or low in aliases:
        return
    if "$" in image:
        res["unknown"] += 1
        return
    if "@sha256:" in low:
        return
    name = low.rsplit("/", 1)[-1]
    tag = name.split(":", 1)[1] if ":" in name else ""
    if tag in ("", "latest"):
        res["findings"].append(make_finding(
            "SEC-INFRA-002", f"Imagen base sin versión fija: {image}", "low", "high", "local_observation",
            tool="sc-local", rule_id="docker-unpinned-base", file=rel, start_line=line,
            description="La imagen base usa 'latest' o no especifica etiqueta.",
            evidence=f"FROM {image}",
            risk="Builds no reproducibles y posibles cambios no revisados en la imagen base.",
            remediation="Fijar una versión concreta o un digest (@sha256:...).",
            mappings=by_id()["SEC-INFRA-002"]["mappings"], in_scope=in_scope))


def docker_control_status(res: Dict[str, Any], what: str) -> Tuple[str, str]:
    if res["checked"] == 0:
        return "NOT_APPLICABLE", "No se detectaron Dockerfiles en el alcance."
    if res["findings"]:
        return "FAIL", f"{len(res['findings'])} incumplimiento(s) en {what}."
    if res["unknown"]:
        return "UNKNOWN", "Hay instrucciones con variables que no se pueden resolver estáticamente."
    return "PASS", f"{res['checked']} Dockerfile(s)/stage(s) verificados."
