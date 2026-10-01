"""Evaluación de controles y gate reproducible.

Estados de control: PASS, FAIL, UNKNOWN, NOT_APPLICABLE, NOT_RUN, ERROR.
Gate global (precedencia): BLOCKED > INCOMPLETE > PASS_WITH_WARNINGS > PASS.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Set

from . import errors
from .findings import SEV_RANK, SEVERITIES

INCOMPLETE_STATES = {"UNKNOWN", "NOT_RUN", "ERROR"}


def exit_code_for(gate_status: str, mode: str) -> int:
    """Código de salida estable. advisory siempre 0 (los errores técnicos usan 2 antes de llegar aquí)."""
    if mode != "enforce":
        return errors.EXIT_OK
    return {"BLOCKED": errors.EXIT_BLOCKED, "INCOMPLETE": errors.EXIT_INCOMPLETE}.get(gate_status, errors.EXIT_OK)


def combine_exit(technical_error: bool, gate_status: str, mode: str) -> int:
    """Precedencia: error técnico (2) > bloqueo (1) > incompleto (3) > ok (0)."""
    return errors.EXIT_ERROR if technical_error else exit_code_for(gate_status, mode)


def _result(c: Dict[str, Any], status: str, reason: str, source: str, *, provenance=None, finding_ids=None,
            evidence_ids=None, limitations=None) -> Dict[str, Any]:
    return {"control_id": c["id"], "title": c["title"], "domain": c["domain"], "method": c["method"],
            "status": status, "reason": reason, "source": source, "provenance": provenance or [],
            "finding_ids": finding_ids or [], "evidence_ids": evidence_ids or [], "required": False,
            "selection": c.get("selection", ""), "supporting": c.get("selection", "").startswith("soporte"),
            "limitations": limitations or [], "exception": None,
            "review_procedure": c.get("review_procedure", []) if c["method"] == "agent" else []}


# ------------------------------------------------------------------ evaluación por método

def _scanner_control(c, runs, findings, cfg):
    cap = c["scanner_capability"]
    run = runs.get(cap)
    fids = [f["id"] for f in findings if f["control_id"] == c["id"] and f["origin"] == "scanner" and f["in_scope"]]
    if run is None:
        return _result(c, "NOT_RUN", f"Capacidad '{cap}' desactivada por configuración (tools.{cap}=off).", "none")
    st = run["status"]
    prov = ["scanner"]
    if st in ("clean", "findings"):
        blocking_conf = [f for f in findings if f["id"] in fids and f["confidence"] != "low"]
        if blocking_conf:
            return _result(c, "FAIL", f"{run['tool']} {run['version'] or ''} reportó {len(blocking_conf)} hallazgo(s) en el alcance.".replace("  ", " "),
                           "scanner", provenance=prov, finding_ids=fids)
        if run.get("partial"):
            return _result(c, "UNKNOWN", f"{run['tool']} analizó con errores parciales: cobertura incompleta.",
                           "scanner", provenance=prov, finding_ids=fids)
        if fids:   # el scanner reportó algo, aunque sea de baja confianza: nunca PASS; requiere triage
            return _result(c, "UNKNOWN", f"{run['tool']} reportó {len(fids)} hallazgo(s) de baja confianza pendientes de triage; "
                           "no se puede afirmar PASS.", "scanner", provenance=prov, finding_ids=fids)
        extra = ""
        return _result(c, "PASS", f"{run['tool']} {run['version'] or ''} analizó el alcance ({run['scope']}) sin "
                       f"hallazgos confirmables{extra}.".replace("  ", " "), "scanner", provenance=prov, finding_ids=fids)
    if st == "no_packages":
        return _result(c, "UNKNOWN", f"{run['tool']} no encontró elementos que analizar: sin cobertura.", "scanner", provenance=prov)
    if st in ("missing", "skipped_policy"):
        why = "; ".join(run["notes"]) or ("herramienta no disponible" if st == "missing" else "omitida por política")
        return _result(c, "NOT_RUN", f"{run['tool']}: {why}", "none")
    return _result(c, "ERROR", f"{run['tool']}: {run.get('error') or st}", "scanner", provenance=prov)


def _local_control(c, local, findings):
    kind = c["local_check"]
    if kind == "lockfiles":
        r = local["lockfiles"]
        status, reason, fl = r["status"], r["reason"], r["findings"]
    else:
        key = "SEC-INFRA-001" if kind == "docker_root" else "SEC-INFRA-002"
        from .localchecks import docker_control_status
        status, reason = docker_control_status(local["docker"][key], "Dockerfiles")
        fl = local["docker"][key]["findings"]
    in_scope = [f["id"] for f in fl if f["in_scope"]]
    if status == "FAIL" and not in_scope:
        status, reason = "PASS", reason + " Todos fuera del alcance revisado (no introducidos por el cambio)."
    status_ids = in_scope
    prov = ["local_observation"] if status != "NOT_APPLICABLE" else []
    return _result(c, status, reason, "local_observation" if prov else "none", provenance=prov, finding_ids=status_ids)


def _agent_control(c, review_info):
    if review_info is None:
        return _result(c, "NOT_RUN", "Requiere revisión del agente: no se importó ninguna (--review).", "none")
    if not review_info["accepted"]:
        return _result(c, "UNKNOWN", "Revisión del agente rechazada: " + review_info["reason"], "none")
    cr = review_info["control_results"].get(c["id"])
    if cr is None:
        return _result(c, "NOT_RUN", "La revisión importada no cubre este control.", "none")
    if cr["status"] == "NOT_APPLICABLE":
        return _result(c, "NOT_APPLICABLE", "Según la revisión del agente: " + cr["rationale"], "agent_review",
                       provenance=["agent_review"], limitations=[cr["limitations"]] if cr["limitations"] else [])
    return _result(c, cr["status"], "Revisión del agente (no verificada de forma independiente): " + cr["rationale"],
                   "agent_review", provenance=["agent_review"], finding_ids=cr["finding_ids"],
                   limitations=[cr["limitations"]] if cr["limitations"] else [])


def _items(evidence, types):
    if not evidence:
        return [], [], []
    acc, nonc, rej = [], [], []
    for it in evidence["items"]:
        if it["type"] in types:
            {"accepted": acc, "non_conclusive": nonc, "rejected": rej}[it["validation"]["status"]].append(it)
    return acc, nonc, rej


def _no_usable(types, nonc, rej, local_note=""):
    if not (nonc or rej):
        return ("UNKNOWN", "Sin evidencia aportada (" + ", ".join(types) + ")." + local_note)
    parts = [f"{i['id']}: {i['validation']['reason']}" for i in (rej + nonc)[:4]]
    return ("UNKNOWN", "La evidencia disponible no es concluyente: " + "; ".join(parts))


def _evidence_rule(rule, c, evidence, cfg, local):
    types = c["evidence_types"]
    min_ap = cfg["itgc"]["min_approvals"]
    acc, nonc, rej = _items(evidence, types)
    trust_user = cfg["trust"]["user_supplied_evidence"]

    def untrusted(items):
        return [i for i in items if i["provenance"] == "user_supplied" and not trust_user]

    if rule == "emergency":
        pol = cfg["itgc"]["emergency_change_policy"]
        if pol == "no":
            return "NOT_APPLICABLE", "La política declara que no admite cambios de emergencia (itgc.emergency_change_policy=no).", []
        if pol == "unknown":
            return "UNKNOWN", "No se definió si la política admite cambios de emergencia (itgc.emergency_change_policy=unknown).", []
    usable = [i for i in acc if i not in untrusted(acc)]
    if acc and not usable:
        return "UNKNOWN", "La evidencia es user_supplied y la política confiable no la acepta (trust.user_supplied_evidence=false).", []
    if not usable:
        note = ""
        if rule == "ci_test" and local.get("workflows"):
            note = (" Se detectaron workflows (" + ", ".join(local["workflows"][:3]) +
                    ") pero un archivo de workflow no prueba que se ejecutó.")
        s, r = _no_usable(types, nonc, rej, note)
        return s, r, []
    ids = [i["id"] for i in usable]

    if rule == "traceability":
        tick = [t for i in usable for t in ((i.get("details") or {}).get("linked_tickets") or [])]
        return ("PASS", f"El PR referencia {len(tick)} ticket(s).", ids) if tick else (
            "FAIL", "El PR no referencia ningún ticket/requerimiento.", ids)
    if rule in ("ci_test", "security_ci"):
        kinds = ("test", "tests") if rule == "ci_test" else ("security", "sast", "sca")
        runs = [i for i in usable if str((i.get("details") or {}).get("kind", "")).lower() in kinds]
        if not runs:
            return "UNKNOWN", "Las ejecuciones de CI aportadas no indican kind=" + "/".join(kinds) + ".", ids
        bad = [i for i in runs if str((i.get("details") or {}).get("conclusion", "")).lower() != "success"]
        if bad:
            return "FAIL", "Ejecución(es) sin éxito: " + ", ".join(f"{i['id']}={i['details'].get('conclusion')}" for i in bad[:3]), ids
        return "PASS", f"{len(runs)} ejecución(es) exitosa(s) sobre el commit evaluado.", ids
    if rule == "approval":
        item = sorted(usable, key=lambda i: i["timestamp"])[-1]
        d = item.get("details") or {}
        author = str(d.get("author", "")).lower()
        head = item.get("commit_sha", "")
        approved = [a for a in (d.get("approvals") or []) if str(a.get("state", "")).lower() == "approved"]
        valid, stale, selfa = set(), 0, 0
        for a in approved:
            actor = str(a.get("actor", "")).lower()
            if actor and actor == author:
                selfa += 1
                continue
            sha = a.get("commit_sha")
            if sha and not head.lower().startswith(str(sha).lower()[:7]):
                stale += 1
                continue
            if actor:
                valid.add(actor)
        if len(valid) >= min_ap:
            return "PASS", f"{len(valid)} aprobación(es) independiente(s) vigente(s) sobre el commit evaluado.", ids
        if selfa and not stale:
            return "FAIL", "Solo existe autoaprobación (el aprobador es el autor).", ids
        if stale:
            return "UNKNOWN", f"{stale} aprobación(es) corresponden a commits anteriores (posiblemente obsoletas); falta aprobación sobre el commit final.", ids
        if d.get("merged"):
            return "FAIL", "El cambio figura integrado sin aprobaciones independientes registradas.", ids
        return "UNKNOWN", "Sin aprobaciones independientes registradas todavía.", ids
    if rule == "change_mgmt":
        a_acc, _, _ = _items(evidence, ["pr_approval"])
        c_acc, _, _ = _items(evidence, ["ci_run"])
        sub = []
        for r in ("approval", "ci_test"):
            cc = dict(c)
            cc["evidence_types"] = ["pr_approval"] if r == "approval" else ["ci_run"]
            sub.append(_evidence_rule(r, cc, evidence, cfg, local))
        sts = [s[0] for s in sub]
        ids2 = sorted({x for s in sub for x in s[2]})
        if "FAIL" in sts:
            return "FAIL", "; ".join(s[1] for s in sub if s[0] == "FAIL"), ids2
        if all(s == "PASS" for s in sts):
            return "PASS", "Revisión independiente y pruebas exitosas sobre el commit evaluado.", ids2
        return "UNKNOWN", "; ".join(s[1] for s in sub if s[0] != "PASS"), ids2
    if rule == "branch_protection":
        item = sorted(usable, key=lambda i: i["timestamp"])[-1]
        d = item.get("details") or {}
        problems = []
        if int(d.get("required_approvals", 0) or 0) < min_ap:
            problems.append(f"exige {d.get('required_approvals', 0)} aprobación(es) (< {min_ap})")
        if not d.get("enforce_admins", False):
            problems.append("no aplica a administradores (enforce_admins=false)")
        if d.get("bypass_actors"):
            problems.append("existen actores con bypass: " + ", ".join(map(str, d["bypass_actors"][:3])))
        return ("FAIL", "Protección de rama insuficiente: " + "; ".join(problems), ids) if problems else (
            "PASS", "La protección de rama exige revisión, aplica a administradores y no declara bypass.", ids)
    if rule == "deployment":
        item = sorted(usable, key=lambda i: i["timestamp"])[-1]
        d = item.get("details") or {}
        missing = [k for k, ok in (("artefacto", item.get("artifact") or d.get("artifact_digest")),
                                    ("aprobador", d.get("approver")), ("ejecutor", d.get("executor")),
                                    ("commit_sha", item.get("commit_sha"))) if not ok]
        return ("UNKNOWN", "Registro de despliegue incompleto, falta: " + ", ".join(missing), ids) if missing else (
            "PASS", "Despliegue trazable a commit/artefacto con aprobador y ejecutor registrados.", ids)
    if rule in ("access_review", "backup", "scheduled_jobs", "organizational"):
        kind = {"backup": "backup_restore", "scheduled_jobs": "scheduled_jobs"}.get(rule)
        sel = [i for i in usable if not kind or str((i.get("details") or {}).get("kind", "")) == kind]
        if not sel:
            return "UNKNOWN", f"La evidencia aportada no es de tipo {kind or c['evidence_types'][0]}.", ids
        res = [i.get("result") for i in sel]
        if "fail" in res:
            return "FAIL", "La evidencia aportada indica resultado negativo.", ids
        if all(r == "pass" for r in res):
            return "PASS", "Evidencia aportada con resultado satisfactorio (autenticidad no verificada).", ids
        return "UNKNOWN", "La evidencia aportada no indica un resultado concluyente.", ids
    if rule == "emergency":
        item = sorted(usable, key=lambda i: i["timestamp"])[-1]
        done = (item.get("details") or {}).get("post_review_completed")
        return ("PASS", "Revisión posterior del cambio de emergencia completada.", ids) if done else (
            "FAIL", "Cambio de emergencia sin revisión posterior registrada.", ids)
    return "UNKNOWN", f"Regla de evidencia sin implementar: {rule}", ids


def _evidence_control(c, evidence, cfg, local):
    status, reason, ids = _evidence_rule(c["evidence_rule"], c, evidence, cfg, local)
    prov = sorted({i["provenance"] for i in (evidence or {"items": []})["items"] if i["id"] in ids})
    return _result(c, status, reason, "evidence" if ids else "none", provenance=prov, evidence_ids=ids)


def _derived_control(c, results):
    subs = [results[d] for d in c["derived_from"] if d in results]
    st = [s["status"] for s in subs]
    app = [s for s in subs if s["status"] != "NOT_APPLICABLE"]
    if not app:
        status, reason = "NOT_APPLICABLE", "Ningún control subyacente aplica en el alcance."
    elif any(s["status"] == "FAIL" for s in app):
        status = "FAIL"
        reason = "Controles subyacentes con FAIL: " + ", ".join(s["control_id"] for s in app if s["status"] == "FAIL")
    elif all(s["status"] == "PASS" for s in app):
        status, reason = "PASS", "Todos los controles técnicos subyacentes aplicables están en PASS."
    else:
        pend = [s["control_id"] for s in app if s["status"] != "PASS"]
        status = "NOT_RUN" if all(s["status"] == "NOT_RUN" for s in app) else "UNKNOWN"
        reason = "Controles subyacentes sin concluir: " + ", ".join(pend)
    prov = sorted({p for s in subs for p in s["provenance"]})
    fids = sorted({f for s in subs for f in s["finding_ids"]})
    return _result(c, status, reason + " (estado derivado; no incluye evidencia organizacional del SGSI).", "derived",
                   provenance=prov, finding_ids=fids, evidence_ids=sorted({e for s in subs for e in s["evidence_ids"]}))


# ------------------------------------------------------------------ evaluación completa

def evaluate_controls(selected: List[Dict[str, Any]], cfg: Dict[str, Any], ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = ctx["findings"]
    results: Dict[str, Dict[str, Any]] = {}
    order = sorted(selected, key=lambda c: (c["method"] == "derived", c["id"]))   # derivados al final
    sox = cfg["project"]["sox_scope"]
    stacks = ctx["stacks"]
    for c in order:
        app = c["applicability"]
        r: Optional[Dict[str, Any]] = None
        if app["requires_sox_scope"]:
            if sox == "no":
                r = _result(c, "NOT_APPLICABLE", "Alcance SOX declarado como 'no' (project.sox_scope=no).", "none")
            elif sox == "unknown":
                r = _result(c, "UNKNOWN", "Alcance SOX no definido (project.sox_scope=unknown): no se infiere aplicabilidad.", "none")
        if r is None and app["requires_stacks"] and not (set(app["requires_stacks"]) & set(stacks)):
            r = _result(c, "NOT_APPLICABLE", "No se detectó en el alcance: " + ", ".join(app["requires_stacks"]) + ".", "local_observation",
                        provenance=["local_observation"])
        if r is None:
            m = c["method"]
            if m == "scanner":
                r = _scanner_control(c, ctx["tool_runs"], findings, cfg)
            elif m == "local":
                r = _local_control(c, ctx["local"], findings)
            elif m == "agent":
                r = _agent_control(c, ctx["review"])
            elif m == "evidence":
                r = _evidence_control(c, ctx["evidence"], cfg, ctx["local"])
            elif m == "derived":
                r = _derived_control(c, results)
        r["limitations"] = list(c["limitations"]) + [x for x in r["limitations"] if x]
        r["required"] = c["id"] in cfg["gate"]["required_controls"]
        results[c["id"]] = r
    return [results[c["id"]] for c in selected]


def apply_exceptions(cfg: Dict[str, Any], findings: List[Dict[str, Any]], results: List[Dict[str, Any]],
                     enforce: bool, today: Optional[date] = None) -> List[str]:
    """Marca hallazgos/controles con excepción válida. Devuelve advertencias."""
    warnings: List[str] = []
    today = today or datetime.now(timezone.utc).date()
    trusted = cfg.get("_exceptions_trusted", False)
    excs = cfg.get("exceptions") or []
    if excs and enforce and not trusted:
        warnings.append("Excepciones del proyecto ignoradas en modo enforce: solo una política confiable puede definirlas.")
        return warnings
    for ex in excs:
        try:
            expires = date.fromisoformat(ex["expires"])
        except ValueError:
            warnings.append(f"Excepción {ex['id']}: fecha de vencimiento inválida; ignorada.")
            continue
        if expires < today:
            warnings.append(f"Excepción {ex['id']} vencida el {ex['expires']}; ignorada.")
            continue
        sc = ex["scope"]
        applied = 0
        for f in findings:
            if sc.get("finding_id") and f["id"] != sc["finding_id"]:
                continue
            if sc.get("control_id") and f["control_id"] != sc["control_id"]:
                continue
            if sc.get("file") and f["file"] != sc["file"]:
                continue
            if not (sc.get("finding_id") or sc.get("control_id") or sc.get("file")):
                continue
            f["exception"] = {"id": ex["id"], "owner": ex["owner"], "expires": ex["expires"],
                              "reason": ex["reason"], "origin": ex.get("origin", ""),
                              "provenance": "trusted_policy" if trusted else "project_config"}
            applied += 1
        if sc.get("control_id") and not sc.get("finding_id") and not sc.get("file"):
            for r in results:
                if r["control_id"] == sc["control_id"]:
                    r["exception"] = {"id": ex["id"], "owner": ex["owner"], "expires": ex["expires"],
                                      "reason": ex["reason"], "origin": ex.get("origin", "")}
                    applied += 1
        if not applied:
            warnings.append(f"Excepción {ex['id']} no coincide con ningún hallazgo/control de esta ejecución.")
    return warnings


def compute_gate(cfg: Dict[str, Any], results: List[Dict[str, Any]], findings: List[Dict[str, Any]], *,
                 mode: str, scope_empty: bool, snapshot_consistent: bool, warnings: List[str],
                 extra_incomplete: Optional[List[str]] = None) -> Dict[str, Any]:
    block_sev: Set[str] = set(cfg["gate"]["block_severities"])
    unknown_policy = cfg["gate"]["unknown_required"]
    reasons: List[str] = []
    blocking_findings = [f["id"] for f in findings
                         if f["in_scope"] and f["severity"] in block_sev and f["confidence"] != "low"
                         and f["origin"] != "heuristic" and f["review_status"] not in ("false_positive",)
                         and not f["exception"]]
    blocked_controls, incomplete_controls = [], []
    for r in results:
        if r["exception"] or r["status"] == "NOT_APPLICABLE":
            continue
        if r["required"]:
            if r["status"] == "FAIL":
                blocked_controls.append(r["control_id"])
                reasons.append(f"Control obligatorio {r['control_id']} en FAIL.")
            elif r["status"] != "PASS":
                if unknown_policy == "block":
                    blocked_controls.append(r["control_id"])
                    reasons.append(f"Control obligatorio {r['control_id']} sin verificar ({r['status']}) y unknown_required=block.")
                else:
                    incomplete_controls.append(r["control_id"])
        if r["status"] in INCOMPLETE_STATES and r["control_id"] not in blocked_controls:
            incomplete_controls.append(r["control_id"])
    if blocking_findings:
        reasons.append(f"{len(blocking_findings)} hallazgo(s) con severidad en ({', '.join(sorted(block_sev, key=SEVERITIES.index))}) y confianza no baja.")

    inc_reasons: List[str] = list(extra_incomplete or [])
    if scope_empty:
        inc_reasons.append("El alcance evaluado está vacío: no hay nada que revisar.")
    if not snapshot_consistent:
        inc_reasons.append("El snapshot cambió durante la revisión: el resultado no corresponde a un estado estable.")
    if not any(r["status"] in ("PASS", "FAIL") for r in results):
        inc_reasons.append("Ningún control evaluable produjo PASS/FAIL.")
    if incomplete_controls:
        inc_reasons.append(f"{len(set(incomplete_controls))} control(es) seleccionados sin concluir (UNKNOWN/NOT_RUN/ERROR).")

    soft = [f for f in findings if f["in_scope"] and not f["exception"] and f["review_status"] != "false_positive"
            and f["id"] not in blocking_findings]
    fail_ctrl = [r["control_id"] for r in results if r["status"] == "FAIL" and not r["exception"]
                 and r["control_id"] not in blocked_controls]
    warn_reasons: List[str] = list(warnings)
    if soft:
        warn_reasons.append(f"{len(soft)} hallazgo(s) no bloqueantes (bajo el umbral, de baja confianza o heurísticos).")
    if fail_ctrl:
        warn_reasons.append("Controles en FAIL no obligatorios: " + ", ".join(fail_ctrl))

    if blocking_findings or blocked_controls:
        status = "BLOCKED"
    elif inc_reasons:
        status = "INCOMPLETE"
    elif warn_reasons:
        status = "PASS_WITH_WARNINGS"
    else:
        status = "PASS"
    return {"status": status, "mode": mode, "exit_code": exit_code_for(status, mode),
            "blocking_findings": sorted(blocking_findings), "blocking_controls": sorted(set(blocked_controls)),
            "incomplete_controls": sorted(set(incomplete_controls)),
            "reasons": reasons + inc_reasons + ([] if status == "BLOCKED" else warn_reasons),
            "policy": {"block_severities": sorted(block_sev, key=SEVERITIES.index),
                       "required_controls": list(cfg["gate"]["required_controls"]),
                       "unknown_required": unknown_policy}}
