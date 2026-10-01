"""Importación y validación de evidencia de PR/CI y de la revisión estructurada del agente."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import SKILL_ROOT, schema as sch
from .catalog import by_id
from .errors import EvidenceError
from .findings import make_finding
from .gitutil import normalize_repo
from .redact import sanitize_obj, sanitize_text

SHA_BOUND = {"pr_metadata", "pr_approval", "ci_run", "deployment_record"}


def _load_json(path: Path, schema_name: str, label: str) -> Dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvidenceError(f"No se pudo leer {label} {path}: {exc}") from exc
    if len(raw) > 5_000_000:
        raise EvidenceError(f"{label} {path.name} excede 5 MB")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise EvidenceError(f"{label} {path.name} no es JSON válido: {exc}") from exc
    errors = sch.validate(data, sch.load_schema(SKILL_ROOT / "schemas" / schema_name))
    if errors:
        raise EvidenceError(f"{label} {path.name} no cumple el schema:\n  - " + "\n  - ".join(errors[:12]))
    return data


def _parse_ts(value: str) -> Optional[datetime]:
    v = value.strip().replace(" ", "T")
    if v.endswith(("Z", "z")):
        v = v[:-1] + "+00:00"
    if len(v) >= 5 and v[-5] in "+-" and v[-3] != ":":
        v = v[:-2] + ":" + v[-2:]
    try:
        d = datetime.fromisoformat(v)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _sha_matches(claimed: str, actual: Optional[str]) -> bool:
    if not actual:
        return False
    c, a = claimed.lower(), actual.lower()
    return len(c) >= 7 and a.startswith(c)


# ------------------------------------------------------------------ evidencia

def import_evidence(paths: List[Path], project: Dict[str, Any], git: Dict[str, Any], now: Optional[datetime] = None,
                    expected_head: Optional[str] = None) -> Dict[str, Any]:
    """Valida cada ítem y devuelve {items:[…con 'validation'], files:[…], warnings:[…]}.

    Validation.status: accepted | non_conclusive | rejected. La procedencia efectiva se limita a
    'user_supplied' (o la declarada si es local_observation/scanner/agent_review): sin conector real,
    'provider_verified' declarado por un archivo no es verificable y se degrada.
    """
    now = now or datetime.now(timezone.utc)
    own_repo = normalize_repo(project.get("repo") or "") or git.get("remote_repo") or ""
    head = expected_head or git.get("head_sha")
    out: Dict[str, Any] = {"items": [], "files": [], "warnings": [], "head_mismatch": False}
    commit_time = _parse_ts(git["commit_time"]) if git.get("commit_time") else None

    for path in paths:
        doc = _load_json(path, "evidence.schema.json", "evidencia")
        doc = sanitize_obj(doc, 1500)
        out["files"].append({"file": path.name, "collected_at": doc["collected_at"],
                             "collector": doc.get("collector"), "items": len(doc["items"])})
        file_repo = normalize_repo(doc["project"]["repo"])
        pr = doc.get("pull_request") or {}
        file_issue = None
        if own_repo and file_repo != own_repo:
            file_issue = ("rejected", f"el repositorio de la evidencia ({file_repo}) no corresponde al proyecto ({own_repo})")
        elif not own_repo:
            file_issue = ("non_conclusive", "no se pudo determinar el repositorio del proyecto; configure project.repo")
        elif pr.get("head_sha") and head and not _sha_matches(pr["head_sha"], head):
            file_issue = ("non_conclusive", f"el head SHA del PR ({pr['head_sha'][:12]}) no coincide con HEAD ({head[:12]})")
            out["head_mismatch"] = True
        elif pr.get("head_sha") and not head:
            file_issue = ("non_conclusive", "el proyecto no tiene commits: no se puede validar el head SHA")

        for item in doc["items"]:
            item = dict(item)
            declared = item["provenance"]
            effective = declared
            notes: List[str] = []
            if declared == "provider_verified":
                effective = "user_supplied"
                notes.append("procedencia 'provider_verified' declarada en un archivo: no verificable sin un "
                             "conector autenticado; se trata como user_supplied")
            status, reason = "accepted", ""
            if file_issue:
                status, reason = file_issue
            else:
                ts = _parse_ts(item["timestamp"])
                if ts is None:
                    status, reason = "non_conclusive", "timestamp no interpretable"
                elif ts > now + timedelta(minutes=10):
                    status, reason = "non_conclusive", "timestamp en el futuro"
                elif item["type"] in SHA_BOUND:
                    sha = item.get("commit_sha")
                    if not sha:
                        status, reason = "non_conclusive", "falta commit_sha para evidencia ligada al commit"
                    elif not _sha_matches(sha, head):
                        status, reason = "non_conclusive", (
                            f"commit_sha {sha[:12]} no coincide con HEAD {(head or 'n/a')[:12]} (evidencia de otro commit)")
                    elif git.get("dirty"):
                        status, reason = "non_conclusive", "el árbol de trabajo tiene cambios locales no cubiertos por el commit de la evidencia"
                    elif commit_time and ts < commit_time - timedelta(seconds=1):
                        status, reason = "non_conclusive", "evidencia anterior a la fecha del commit evaluado"
            item["provenance_declared"] = declared
            item["provenance"] = effective
            item["validation"] = {"status": status, "reason": reason, "notes": notes}
            item["origin_file"] = path.name
            out["items"].append(item)
    return out


# ------------------------------------------------------------------ revisión del agente

def import_review(path: Path, selected_ids: List[str], snapshot: Dict[str, Any], git: Dict[str, Any],
                  inventory_files: Dict[str, Dict[str, Any]], root: Path, trusted: bool,
                  inside_project: bool) -> Dict[str, Any]:
    """Valida la revisión del agente. Devuelve {accepted, control_results, findings, rejected, warnings}."""
    doc = sanitize_obj(_load_json(path, "review.schema.json", "revisión"), 3000)
    cat = by_id()
    res: Dict[str, Any] = {"accepted": False, "reason": "", "control_results": {}, "findings": [], "rejected": [],
                           "warnings": [], "reviewer": doc["reviewer"], "created_at": doc["created_at"],
                           "file": path.name, "inside_project": inside_project}
    snap = doc["snapshot"]
    if not snap.get("snapshot_hash") and not snap.get("head_sha"):
        res["reason"] = "la revisión no declara snapshot_hash ni head_sha: no se puede vincular al snapshot"
        return res
    if snap.get("snapshot_hash"):
        if snap["snapshot_hash"] != snapshot["snapshot_hash"]:
            res["reason"] = ("el snapshot_hash de la revisión no coincide con el snapshot actual (el código cambió "
                             "o la revisión es de otra ejecución)")
            return res
    elif git.get("dirty") or not _sha_matches(snap["head_sha"], git.get("head_sha")):
        res["reason"] = ("head_sha de la revisión no coincide con HEAD, o el árbol tiene cambios locales (use "
                         "snapshot_hash)")
        return res
    if not trusted:
        res["reason"] = ("revisión no confiable: en modo enforce una revisión aportada con el cambio solo se acepta "
                         "si la política confiable lo permite (trust.agent_review)")
        return res
    res["accepted"] = True
    if inside_project:
        res["warnings"].append("el archivo de revisión está dentro del proyecto auditado")

    refs: Dict[str, str] = {}
    for f in doc.get("findings") or []:
        why = _finding_problem(f, cat, selected_ids, inventory_files, root)
        if why:
            res["rejected"].append({"ref": f["ref"], "reason": why})
            continue
        fid = make_finding(
            f["control_id"], f["title"], f["severity"], f["confidence"], "agent_review", tool=doc["reviewer"]["client"],
            rule_id=None, file=f["file"], start_line=f.get("start_line"), end_line=f.get("end_line"),
            description=f["description"] + (("\nFlujo: " + f["flow"]) if f.get("flow") else ""),
            evidence=f.get("evidence", ""), risk=f.get("risk", ""), remediation=f.get("remediation", ""),
            mappings=cat[f["control_id"]]["mappings"], extra_key=f["ref"])
        refs[f["ref"]] = fid["id"]
        res["findings"].append(fid)

    for cr in doc["control_results"]:
        cid = cr["control_id"]
        if cid not in cat:
            res["rejected"].append({"ref": cid, "reason": "control inexistente en el catálogo"})
            continue
        if cid not in selected_ids:
            res["rejected"].append({"ref": cid, "reason": "control no seleccionado en esta ejecución"})
            continue
        c = cat[cid]
        if c["method"] not in ("agent",):
            res["rejected"].append({"ref": cid, "reason": f"control de método '{c['method']}': solo se resuelve "
                                    "con scanner/evidencia/derivación, no con una afirmación del agente"})
            continue
        linked = [refs[r] for r in cr.get("finding_refs", []) if r in refs]
        own = [x["id"] for x in res["findings"] if x["control_id"] == cid]
        linked = sorted(set(linked + own))
        if cr["status"] == "FAIL" and not linked:
            res["rejected"].append({"ref": cid, "reason": "FAIL requiere al menos un hallazgo válido con archivo/evidencia"})
            continue
        if cr["status"] == "PASS" and not (cr.get("files_examined") or doc.get("scope_reviewed")):
            res["rejected"].append({"ref": cid, "reason": "PASS requiere files_examined (qué se leyó) para ser auditable"})
            continue
        res["control_results"][cid] = {"status": cr["status"], "rationale": cr["rationale"],
                                       "files_examined": cr.get("files_examined", []), "finding_ids": linked,
                                       "limitations": cr.get("limitations", "")}
    return res


def _finding_problem(f: Dict[str, Any], cat: Dict[str, Any], selected: List[str],
                     inv: Dict[str, Dict[str, Any]], root: Path) -> str:
    cid = f["control_id"]
    if cid not in cat:
        return "control inexistente en el catálogo"
    if cid not in selected:
        return "control no seleccionado en esta ejecución"
    p = f["file"].replace("\\", "/")
    if p.startswith("/") or ".." in p.split("/") or ":" in p[:3]:
        return "ruta fuera del alcance del proyecto"
    if p not in inv:
        return "el archivo no existe en el snapshot (posible hallazgo inventado)"
    if f.get("start_line"):
        try:
            n = sum(1 for _ in open(root / p, "rb"))
        except OSError:
            n = 0
        if f["start_line"] > max(n, 1):
            return f"la línea {f['start_line']} excede el tamaño del archivo ({n} líneas)"
    return ""
