"""Progreso entre ejecuciones: qué se resolvió, qué persiste, qué es nuevo y qué quedó sin reverificar.

Regla clave: un hallazgo previo solo cuenta como **resuelto** si su control volvió a evaluarse (PASS/FAIL) en la
nueva ejecución y el hallazgo ya no aparece. Si el control quedó NOT_RUN/UNKNOWN/ERROR (p. ej. el código cambió y
la revisión del agente no se repitió, o falta un scanner), el hallazgo pasa a "sin reverificar": ausencia de
evidencia no es una corrección. No altera conclusiones ni el gate de la ejecución actual.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .findings import SEV_RANK, SEVERITIES
from . import schema as sch

VERIFIED = ("PASS", "FAIL")
HISTORY_LIMIT = 20


def fingerprint(f: Dict[str, Any]) -> str:
    """Identidad base de un hallazgo entre ejecuciones (no depende del número de línea).

    Los hallazgos del agente se identifican por control + archivo (el texto y el cliente varían entre
    revisiones); los de scanner/local, por herramienta + regla + archivo + título.
    """
    if f["origin"] == "agent_review":
        return "|".join([f["control_id"], "agent_review", f.get("file") or ""])
    return "|".join([f["control_id"], f.get("tool") or f["origin"], f.get("rule_id") or "", f.get("file") or "",
                     " ".join((f.get("title") or "").lower().split())[:160]])


def fingerprints(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """fingerprint → hallazgo, con ordinal (#n, por línea) cuando varios comparten la misma identidad base."""
    out: Dict[str, Dict[str, Any]] = {}
    seen: Dict[str, int] = {}
    for f in sorted(findings, key=lambda x: (fingerprint(x), x.get("start_line") or 0, x["id"])):
        base = fingerprint(f)
        seen[base] = seen.get(base, 0) + 1
        out[base if seen[base] == 1 else f"{base}#{seen[base]}"] = f
    return out


def _brief(f: Dict[str, Any], fp: str) -> Dict[str, Any]:
    return {"id": f["id"], "fingerprint": fp, "control_id": f["control_id"], "severity": f["severity"],
            "title": f["title"], "file": f.get("file"), "start_line": f.get("start_line"), "origin": f["origin"]}


def _counted(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [f for f in report["findings"] if f["in_scope"]]


def list_previous(out_root: Path, command: str, project_name: str, exclude_run: str = "") -> List[Dict[str, Any]]:
    """Reportes válidos anteriores del mismo comando y proyecto, del más antiguo al más reciente."""
    from .report import load_run   # import tardío (evita ciclo)
    out: List[Dict[str, Any]] = []
    if not out_root.is_dir():
        return out
    # orden cronológico: marca de tiempo del run_id y, si coincide el segundo, la hora de creación del directorio
    dirs = sorted((p for p in out_root.iterdir() if p.is_dir() and p.name != exclude_run),
                  key=lambda p: (p.name[:16], p.stat().st_mtime_ns))
    for d in dirs:
        try:
            rep = load_run(d)
        except Exception:   # un reporte ilegible o de otra versión no rompe la nueva ejecución
            continue
        rep.pop("_integrity", None)
        if rep["command"] == command and rep["project"]["name"] == project_name:
            out.append(rep)
    return out


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    fs = _counted(report)
    return {"run_id": report["run_id"], "generated_at": report["generated_at"], "gate": report["gate"]["status"],
            "findings": {s: sum(1 for f in fs if f["severity"] == s) for s in SEVERITIES},
            "controls": dict(report["coverage"]["by_status"])}


def compute(current: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if previous is None:
        return {"has_previous": False}
    cur = fingerprints(_counted(current))
    # Problemas conocidos de la ejecución anterior = sus hallazgos + los que ella no pudo reverificar (arrastre):
    # así, corregir → reverificar en una corrida posterior sí se reconoce como «resuelto».
    prev = {fp: _brief(f, fp) for fp, f in fingerprints(_counted(previous)).items()}
    for b in (previous.get("progress") or {}).get("not_reverified", []):
        prev.setdefault(b["fingerprint"], {k: v for k, v in b.items() if k != "control_status_now"})
    cur_status = {c["control_id"]: c["status"] for c in current["controls"]}
    resolved, persistent, new, unverified = [], [], [], []
    for fp, b in prev.items():
        if fp in cur:
            persistent.append(_brief(cur[fp], fp))
        elif cur_status.get(b["control_id"]) in VERIFIED:
            resolved.append(b)
        else:
            ub = dict(b)
            ub["control_status_now"] = cur_status.get(b["control_id"], "NO_SELECCIONADO")
            unverified.append(ub)
    for fp, f in cur.items():
        if fp not in prev:
            new.append(_brief(f, fp))
    changes = []
    prev_status = {c["control_id"]: c["status"] for c in previous["controls"]}
    for cid, st in cur_status.items():
        if cid in prev_status and prev_status[cid] != st:
            changes.append({"control_id": cid, "from": prev_status[cid], "to": st})

    def order(items):
        return sorted(items, key=lambda b: (SEV_RANK[b["severity"]], b["control_id"], b["file"] or ""))

    before, after = summarize(previous), summarize(current)
    counts_before = {s: sum(1 for b in prev.values() if b["severity"] == s) for s in SEVERITIES}
    return {"has_previous": True, "previous_run_id": previous["run_id"], "previous_generated_at": previous["generated_at"],
            "previous_snapshot_hash": previous["snapshot"]["snapshot_hash"],
            "gate_before": previous["gate"]["status"], "gate_after": current["gate"]["status"],
            "counts_before": counts_before, "counts_after": after["findings"],
            "controls_before": before["controls"], "controls_after": after["controls"],
            "resolved": order(resolved), "persistent": order(persistent), "new": order(new),
            "not_reverified": order(unverified), "control_changes": sorted(changes, key=lambda c: c["control_id"]),
            "note": ("«Resuelto» = el control se volvió a verificar y el hallazgo ya no aparece. «Sin reverificar» = el control no se "
                     "pudo evaluar en esta ejecución (p. ej. falta repetir la revisión del agente o un scanner), por lo que no se "
                     "puede afirmar que se corrigió; se sigue arrastrando hasta que se reverifique.")}


def history_for(previous_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [summarize(r) for r in previous_reports][-(HISTORY_LIMIT - 1):]
