"""Orquestación de los comandos de revisión: audit, diff, pr, sox, iso, security, secrets, dependencies."""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import catalog, config as cfgmod, evaluate, evidence as evmod, gitutil, inventory as inv, localchecks, progress, report as rep
from . import skill_version
from .errors import ConfigError, ScError, UsageError
from .findings import SEV_RANK
from .redact import display_path
from .tools.base import NO_PACKAGES, utcnow
from .tools.gitleaks import Gitleaks
from .tools.osv import OsvScanner
from .tools.semgrep import Semgrep

REVIEW_COMMANDS = ("audit", "diff", "pr", "sox", "iso", "security", "secrets", "dependencies")
ADAPTERS = {"sast": Semgrep, "secrets": Gitleaks, "dependencies": OsvScanner}

STATIC_LIMITATIONS = [
    "El runner no razona sobre autorización ni arquitectura: los controles de método 'agent' solo se resuelven con una "
    "revisión estructurada importada (procedencia agent_review, no verificada de forma independiente).",
    "Un archivo de workflow o una rama local no prueban ejecución ni protección remota; sin conector autenticado la "
    "evidencia aportada no se verifica de forma independiente.",
    "El skill no ejecuta build, tests ni código del proyecto auditado (se trata como código no confiable).",
]


def _flags(args) -> Dict[str, Any]:
    return {"review.mode": getattr(args, "mode", None)}


def _selected_changed(root: Path, base: Optional[str], cfg, excludes) -> Dict[str, Any]:
    ch = gitutil.changed_files(root, base)
    files = []
    for f in ch["files"]:
        p = f["path"]
        if inv.is_excluded(p, excludes) or not inv._included(p, cfg["paths"]["include"]):
            continue
        files.append(f)
    ch["files"] = files
    return ch


def run_review(command: str, args) -> Dict[str, Any]:
    """Ejecuta la revisión y devuelve {report, run_dir, exit_code, inventory, tool_outputs}."""
    if command not in REVIEW_COMMANDS:
        raise UsageError(f"Comando desconocido: {command}")
    root = Path(args.project or ".").resolve()
    if not root.is_dir():
        raise ConfigError(f"El proyecto {root} no existe o no es un directorio")
    mode_flag = getattr(args, "mode", None)
    policy = Path(args.policy).resolve() if getattr(args, "policy", None) else None
    cfg, meta = cfgmod.load_effective(
        root, Path(args.config).resolve() if getattr(args, "config", None) else None, _flags(args), policy,
        enforce=(mode_flag == "enforce"), allow_project_policy=getattr(args, "allow_project_policy", False))
    mode = cfg["review"]["mode"]
    if mode == "enforce" and meta["policy_source"] != "trusted_policy" and not getattr(args, "allow_project_policy", False):
        raise ConfigError("El modo enforce requiere una política confiable externa (--policy).",
                          "Use --policy <archivo> o --allow-project-policy solo para ejecución local.")
    timeout = getattr(args, "timeout", None) or cfg["tools"]["timeout_seconds"]
    excludes = cfgmod.effective_excludes(cfg)
    out_root = Path(args.output).resolve() if getattr(args, "output", None) else root / cfg["reports"]["directory"]
    try:   # los reportes propios nunca forman parte del alcance auditado (ni de la siguiente ejecución)
        rel_out = out_root.relative_to(root).as_posix()
        if rel_out not in ("", ".") and rel_out not in excludes:
            excludes.append(rel_out)
    except ValueError:
        pass
    warnings: List[str] = list(meta["notes"])
    limitations: List[str] = list(STATIC_LIMITATIONS)

    git = gitutil.git_info(root)
    if not git["is_repo"]:
        warnings.append("El proyecto no es un repositorio Git: trazabilidad parcial (sin commit/branch/diff).")

    # ---- alcance
    changed_info: Optional[Dict[str, Any]] = None
    changed_paths: Optional[set] = None
    if command in ("diff", "pr"):
        base = getattr(args, "base", None)
        if command == "pr":
            if getattr(args, "head", None) and not evmod._sha_matches(args.head, git.get("head_sha")):
                raise ScError(f"El head SHA informado ({args.head[:12]}) no coincide con HEAD "
                              f"({(git.get('head_sha') or 'n/a')[:12]}).",
                              "Haga checkout del head del PR antes de revisarlo; no se revisa un snapshot distinto.")
        changed_info = _selected_changed(root, base, cfg, excludes)
        changed_paths = {f["path"] for f in changed_info["files"]}
        limitations += changed_info["notes"]
        limitations.append("Sin comparación contra una baseline, no se distingue si un hallazgo fue introducido por el "
                           "cambio (baseline_status=unknown); los scanners pueden analizar más que el diff.")
    inventory = inv.build_inventory(root, cfg, excludes)
    if inventory["truncated"]:
        warnings.append(f"Inventario truncado en {inv.MAX_FILES} archivos: cobertura parcial.")
    if inventory["skipped"]:
        limitations.append(f"{len(inventory['skipped'])} archivo(s) omitidos del análisis (symlinks, >2 MB o ilegibles); no cuentan como cobertura.")
    files = inventory["files"]
    stacks = inv.detect_stacks(root, files)
    dep_inv = inv.dependency_inventory(root, files)
    injection_hits = inv.scan_agent_directed_text(root, files)
    if injection_hits:
        warnings.append("Texto dirigido a agentes/IA detectado en: " + ", ".join(injection_hits[:5]) +
                        ". Se trata como DATO del proyecto; no altera políticas, comandos ni conclusiones.")
    scope_empty = (len(changed_paths) == 0) if changed_paths is not None else (inventory["file_count"] == 0)

    # ---- controles seleccionados
    selected = catalog.select_controls(command, cfg["frameworks"])
    sel_ids = [c["id"] for c in selected]

    # ---- scanners requeridos por los controles seleccionados
    caps = sorted({c["scanner_capability"] for c in selected if c["method"] == "scanner"})
    tool_runs: Dict[str, Any] = {}
    run_list: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="sc-work-") as work:
        ctx = {"root": root, "excludes": excludes, "timeout": timeout, "workdir": Path(work),
               "network_allowed": cfg["network"]["allow_external_scanners"], "changed_paths": changed_paths}
        for cap in caps:
            choice = cfg["tools"][cap]
            if choice == "off":
                tool_runs[cap] = None
                continue
            run = ADAPTERS[cap]().run(ctx)
            for f in run["findings"]:
                f["in_scope"] = (changed_paths is None or f["file"] is None or f["file"] in changed_paths)
            tool_runs[cap] = run
            run_list.append(run)
            if cap == "secrets" and run["tool"] == "gitleaks":
                supp = localchecks.count_inline_suppressions(root, files)
                for k, n in supp.items():
                    warnings.append(f"{n} supresión(es) inline '{k}' en el alcance: pueden ocultar hallazgos del scanner.")
    tool_outputs = [{k: v for k, v in r.items() if k != "findings"} | {"finding_count": len(r["findings"])} for r in run_list]

    # ---- comprobaciones locales
    local = {"lockfiles": localchecks.check_lockfiles(dep_inv, changed_paths),
             "docker": localchecks.check_dockerfiles(root, files, changed_paths),
             "workflows": sorted(e["path"] for e in files if e["path"].startswith(".github/workflows/") and e["path"].endswith((".yml", ".yaml")))}
    heur: List[Dict[str, Any]] = []
    if "SEC-SECRETS-001" in sel_ids:
        heur = localchecks.heuristic_secret_candidates(root, files, changed_paths)
        scanner_ok = tool_runs.get("secrets") and tool_runs["secrets"]["status"] in ("clean", "findings")
        if heur and not scanner_ok:
            warnings.append(f"{len(heur)} candidato(s) a secreto por heurística de regex: requieren confirmación con un scanner real.")

    # ---- evidencia y revisión importadas
    ev_paths = [Path(p).resolve() for p in (getattr(args, "evidence", None) or [])]
    evidence = None
    if ev_paths:
        evidence = evmod.import_evidence(ev_paths, cfg["project"], git, expected_head=getattr(args, "head", None))
        warnings.append("La evidencia importada no se verificó de forma independiente (sin conector autenticado): "
                        "su procedencia máxima es user_supplied.")
        if evidence["head_mismatch"]:
            warnings.append("El head SHA del PR en la evidencia no coincide con HEAD: evidencia no concluyente.")
    review_info = None
    review_path = Path(args.review).resolve() if getattr(args, "review", None) else None
    if review_path:
        inside = evmod_inside(review_path, root)
        trusted = cfg["trust"]["agent_review"]
        review_info = evmod.import_review(review_path, sel_ids, inventory, git, {e["path"]: e for e in files}, root,
                                          trusted, inside)
        warnings += review_info["warnings"]

    # ---- hallazgos
    findings: Dict[str, Dict[str, Any]] = {}
    for run in run_list:
        for f in run["findings"]:
            findings[f["id"]] = f
    for f in heur:
        findings.setdefault(f["id"], f)
    for r in list(local["docker"].values()):
        for f in r["findings"]:
            findings[f["id"]] = f
    for f in local["lockfiles"]["findings"]:
        findings[f["id"]] = f
    if review_info and review_info["accepted"]:
        for f in review_info["findings"]:
            f["in_scope"] = changed_paths is None or f["file"] in changed_paths
            findings[f["id"]] = f
    # solo hallazgos de controles seleccionados
    flist = [f for f in findings.values() if f["control_id"] in sel_ids]

    # ---- snapshot final (consistencia)
    git_end = gitutil.git_info(root)
    inv_end = inv.build_inventory(root, cfg, excludes)
    consistent = inv_end["snapshot_hash"] == inventory["snapshot_hash"] and git_end["head_sha"] == git["head_sha"]
    if not consistent:
        warnings.append("HEAD, el índice o los archivos cambiaron durante la revisión: repita sobre un snapshot estable.")

    # ---- evaluación y gate
    results = evaluate.evaluate_controls(selected, cfg, {
        "findings": flist, "tool_runs": tool_runs, "local": local, "stacks": stacks, "evidence": evidence,
        "review": review_info})
    exc_warn = evaluate.apply_exceptions(cfg, flist, results, enforce=(mode == "enforce"))
    warnings += exc_warn
    if evidence and any(i["validation"]["status"] == "accepted" and i["provenance"] == "user_supplied" for i in evidence["items"]):
        pass  # ya advertido arriba
    gate = evaluate.compute_gate(cfg, results, flist, mode=mode, scope_empty=scope_empty,
                                 snapshot_consistent=consistent, warnings=_dedupe(warnings))

    by_status: Dict[str, int] = {s: 0 for s in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "NOT_RUN", "ERROR")}
    for r in results:
        by_status[r["status"]] += 1
    scanner_cov = {}
    for cap in caps:
        run = tool_runs.get(cap)
        scanner_cov[cap] = "desactivado por configuración" if run is None else (
            f"{run['tool']} {run['status']}" + (f" — {run['scope']}" if run.get("scope") else ""))
    run_id = rep.new_run_id()
    sc_hash_end = inv_end["snapshot_hash"]
    report: Dict[str, Any] = {
        "schema_version": 1, "run_id": run_id, "generated_at": utcnow(), "command": command, "mode": mode,
        "skill": {"name": "security-compliance", "version": skill_version()},
        "catalog": {"version": catalog.load_catalog()["catalog_version"], "baselines": catalog.load_catalog()["baselines"]},
        "project": {
            "name": (cfg["project"]["name"] if cfg["project"]["name"] != "auto" else root.name),
            "root": display_path(str(root)), "repo": cfg["project"].get("repo") or git.get("remote_repo") or "",
            "criticality": cfg["project"]["criticality"], "sox_scope": cfg["project"]["sox_scope"],
            "git": {"is_repo": git["is_repo"], "head_sha": git["head_sha"], "branch": git["branch"],
                    "base": (changed_info or {}).get("base"), "merge_base": (changed_info or {}).get("merge_base"),
                    "dirty": git["dirty"], "shallow": git["shallow"]}},
        "snapshot": {"snapshot_hash": inventory["snapshot_hash"], "snapshot_hash_end": sc_hash_end,
                     "file_count": inventory["file_count"], "excluded_count": inventory["excluded_count"],
                     "skipped_count": len(inventory["skipped"]), "consistent": consistent,
                     "scope": "changed_files" if changed_paths is not None else "full",
                     "changed_files": (changed_info or {}).get("files", []), "exclusions": excludes,
                     "include": cfg["paths"]["include"]},
        "config": {"hash": meta["config_hash"], "policy_source": meta["policy_source"], "config_file": meta["config_file"],
                   "policy_file": meta["policy_file"], "notes": meta["notes"],
                   "effective": {k: v for k, v in cfg.items() if not k.startswith("_")}},
        "stacks": stacks,
        "controls": results,
        "findings": sorted(flist, key=lambda f: (SEV_RANK[f["severity"]], f["control_id"], f["file"] or "", f["id"])),
        "scanners": [{k: v for k, v in r.items() if k != "findings"} | {"finding_count": len(r["findings"])} for r in run_list],
        "dependencies": {"manifests": dep_inv["manifests"], "dependency_count": dep_inv["dependency_count"],
                         "dependencies": dep_inv["dependencies"][:500]} if command == "dependencies" else {},
        "evidence": {"provided": bool(evidence), "files": (evidence or {}).get("files", []),
                     "items": (evidence or {}).get("items", []),
                     "authenticity_note": "Evidencia aportada sin conector: autenticidad no verificada de forma independiente; "
                                          "procedencia efectiva máxima user_supplied."},
        "agent_review": _review_block(review_info, review_path),
        "coverage": {"controls_selected": len(results), "by_status": by_status, "scanners": scanner_cov,
                     "asvs": catalog.asvs_coverage(selected, cfg["review"]["asvs_target_level"]),
                     "files_in_scope": len(changed_paths) if changed_paths is not None else inventory["file_count"],
                     "statement": "La cobertura refleja controles evaluados con evidencia; no equivale a conformidad."},
        "gate": gate,
        "exceptions": sorted({e["id"]: e for f in flist if f["exception"] for e in [dict(f["exception"])]}.values(),
                             key=lambda e: e["id"]),
        "limitations": limitations,
        "warnings": _dedupe(warnings),
        "disclaimer": rep.DISCLAIMER,
    }
    # progreso frente a la ejecución anterior del mismo comando/proyecto (no altera conclusiones ni el gate)
    prevs = progress.list_previous(out_root, command, report["project"]["name"])
    report["progress"] = progress.compute(report, prevs[-1] if prevs else None)
    report["history"] = progress.history_for(prevs)
    errs = rep.validate_report(report)
    if errs:  # defecto interno: nunca emitir un reporte que viole el contrato
        raise ScError("Defecto interno: el reporte generado no cumple report.schema.json:\n  - " + "\n  - ".join(errs[:8]))

    run_dir = rep.write_run(report, out_root, inventory, tool_outputs)
    return {"report": report, "run_dir": run_dir, "exit_code": gate["exit_code"], "gitignore_hint": _gitignore_hint(root, run_dir)}


def evmod_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _review_block(info: Optional[Dict[str, Any]], path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {"provided": False, "accepted": False, "provenance": "agent_review"}
    if info is None:
        return {"provided": True, "accepted": False, "provenance": "agent_review"}
    return {"provided": True, "accepted": info["accepted"], "reason": info["reason"], "reviewer": info["reviewer"],
            "file": info["file"], "rejected_entries": info["rejected"], "provenance": "agent_review"}


def _dedupe(items: List[str]) -> List[str]:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _gitignore_hint(root: Path, run_dir: Path) -> Optional[str]:
    try:
        rel = run_dir.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    gi = root / ".gitignore"
    top = rel.parts[0]
    text = gi.read_text(encoding="utf-8", errors="ignore") if gi.is_file() else ""
    if top in text:
        return None
    return (f"Los reportes pueden contener rutas y hallazgos sensibles: considere agregar '{top}/' a .gitignore "
            "(el skill no modifica .gitignore por sí solo).")
