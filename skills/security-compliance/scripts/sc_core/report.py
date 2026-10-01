"""Generación, validación y persistencia de reportes (JSON + Markdown) por run_id."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import SKILL_ROOT, schema as sch
from .errors import ConfigError, ScError
from .findings import SEV_RANK
from .redact import final_scrub, sanitize_text

DISCLAIMER = ("Revisión de controles técnicos basada en la evidencia disponible. No constituye una certificación ni una "
              "afirmación de cumplimiento SOX, ISO/IEC 27001 u OWASP ASVS: la ausencia de evidencia no equivale a "
              "aprobación, y los controles marcados UNKNOWN/NOT_RUN/ERROR no fueron verificados.")


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


def load_report_schema() -> Dict[str, Any]:
    return sch.load_schema(SKILL_ROOT / "schemas" / "report.schema.json")


def validate_report(report: Dict[str, Any]) -> List[str]:
    return sch.validate(report, load_report_schema())


# ------------------------------------------------------------------ Markdown seguro

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>|#!~])")


def md(text: Any) -> str:
    """Texto plano seguro para Markdown: sin HTML, sin enlaces, sin saltos dentro de celdas."""
    s = sanitize_text(str(text if text is not None else ""), 1200)
    s = s.replace("\r", " ").replace("\n", " ")
    s = _MD_SPECIAL.sub(r"\\\1", s)
    return s.strip()


def code(text: Any) -> str:
    s = sanitize_text(str(text if text is not None else ""), 400).replace("\r", " ").replace("\n", " ")
    s = s.replace("`", "'").replace("<", "‹").replace(">", "›").replace("|", "¦")
    return f"`{s}`"


ICON = {"PASS": "✅", "FAIL": "❌", "UNKNOWN": "❓", "NOT_APPLICABLE": "➖", "NOT_RUN": "⏸️", "ERROR": "⚠️"}
GATE_ICON = {"PASS": "✅", "PASS_WITH_WARNINGS": "🟡", "BLOCKED": "⛔", "INCOMPLETE": "🟠"}

RESOLVE = {
    ("scanner", "NOT_RUN"): "Instale o habilite el scanner (ver doctor) y repita; no se instala automáticamente.",
    ("scanner", "ERROR"): "Revise el error del scanner (sección Scanners) y repita.",
    ("scanner", "UNKNOWN"): "El scanner no cubrió el alcance; verifique manifiestos/archivos soportados y repita.",
    ("agent", "NOT_RUN"): "Pida al agente que revise este control y reimporte el resultado con --review.",
    ("agent", "UNKNOWN"): "Repita la revisión del agente sobre el snapshot actual y reimporte con --review.",
    ("evidence", "UNKNOWN"): "Aporte evidencia validada para el commit exacto (--evidence) o defina la aplicabilidad en la configuración.",
    ("derived", "UNKNOWN"): "Resuelva los controles subyacentes listados en el motivo.",
    ("derived", "NOT_RUN"): "Resuelva los controles subyacentes listados en el motivo.",
    ("local", "UNKNOWN"): "Revise manualmente las instrucciones que no se pudieron resolver estáticamente.",
}


def render_markdown(r: Dict[str, Any]) -> str:
    L: List[str] = []
    g = r["gate"]
    L += [f"# Revisión de controles técnicos — {md(r['project']['name'])}", "",
          f"> {md(r['disclaimer'])}", ""]
    L += ["## Resumen", "",
          f"- **Resultado del gate:** {GATE_ICON[g['status']]} `{g['status']}` (modo `{g['mode']}`, código de salida `{g['exit_code']}`)",
          f"- **Comando:** `{r['command']}` · **Run:** {code(r['run_id'])} · **Fecha (UTC):** {md(r['generated_at'])}",
          f"- **Skill:** {md(r['skill']['version'])} · **Catálogo:** {md(r['catalog']['version'])} · **Configuración:** {code(r['config']['hash'])} ({md(r['config']['policy_source'])})", ""]
    if g["reasons"]:
        L += ["**Motivos del resultado:**", ""] + [f"- {md(x)}" for x in g["reasons"]] + [""]

    L += ["## Qué se revisó", ""]
    git = r["project"]["git"]
    L += [f"- **Proyecto:** {md(r['project']['name'])} (raíz {code(r['project']['root'])})"]
    if git["is_repo"]:
        L += [f"- **Git:** rama {code(git.get('branch') or 'n/a')}, HEAD {code((git.get('head_sha') or 'sin commits')[:12])}, "
              f"cambios locales: {md(git.get('dirty'))}" + (f", base {code(git['base'])} (merge-base {code((git.get('merge_base') or '')[:12])})" if git.get("base") else "")]
    else:
        L += ["- **Git:** el proyecto no es un repositorio Git: trazabilidad parcial."]
    s = r["snapshot"]
    L += [f"- **Snapshot:** {code(s['snapshot_hash'])} — {s['file_count']} archivos en alcance, {s['excluded_count']} excluidos, "
          f"{s.get('skipped_count', 0)} omitidos; alcance `{s['scope']}`; estable durante la revisión: **{'sí' if s['consistent'] else 'NO'}**"]
    if r["stacks"]:
        L += ["- **Stacks detectados:** " + ", ".join(f"{md(k)} ({len(v)})" for k, v in r["stacks"].items())]
    else:
        L += ["- **Stacks detectados:** ninguno (no se inventan stacks ausentes)"]
    if s.get("changed_files"):
        L += ["", "**Archivos cambiados** (" + str(len(s["changed_files"])) + "):", ""]
        for f in s["changed_files"][:60]:
            old = f" ← {code(f['old_path'])}" if f.get("old_path") else ""
            L.append(f"- `{f['status']}` {code(f['path'])}{old}")
        if len(s["changed_files"]) > 60:
            L.append(f"- … y {len(s['changed_files']) - 60} más (ver report.json)")
    L += [""]

    L += ["## Cobertura", ""]
    cov = r["coverage"]
    L += [f"- Controles seleccionados: **{cov['controls_selected']}** — " +
          ", ".join(f"{ICON[k]} {k}: {v}" for k, v in cov["by_status"].items() if v)]
    for cap, st in cov["scanners"].items():
        L.append(f"- Scanner `{cap}`: {md(st)}")
    a = cov["asvs"]
    L += [f"- {md(a['baseline'])}: {a['requirements_referenced']} requisitos referenciados por los controles seleccionados "
          f"({a['requirements_referenced_within_target']} de {a['requirements_in_target_level']} dentro del nivel objetivo {a['target_level']}). "
          f"{md(a['statement'])}", ""]

    blocking = set(g["blocking_findings"])
    L += ["## Qué bloquea", ""]
    if g["status"] == "BLOCKED":
        for f in r["findings"]:
            if f["id"] in blocking:
                L.append(f"- ⛔ {code(f['id'])} **{md(f['severity'])}** — {md(f['title'])} ({code(f['file'] or 'proyecto')})")
        for cid in g["blocking_controls"]:
            L.append(f"- ⛔ Control obligatorio {code(cid)}")
    else:
        L.append("Nada bloquea en esta ejecución.")
    L += [""]

    L += ["## Hallazgos", ""]
    fs = sorted(r["findings"], key=lambda f: (SEV_RANK[f["severity"]], f["control_id"], f["file"] or ""))
    if not fs:
        L += ["Sin hallazgos registrados en esta ejecución (no implica ausencia de vulnerabilidades: ver cobertura y controles sin verificar).", ""]
    else:
        L += ["| ID | Severidad | Confianza | Origen | Control | Ubicación | Título | Estado |", "|---|---|---|---|---|---|---|---|"]
        for f in fs:
            loc = (f["file"] or "proyecto") + (f":{f['start_line']}" if f.get("start_line") else "")
            st = ("excepción " + f["exception"]["id"]) if f.get("exception") else ("fuera de alcance" if not f["in_scope"] else
                 ("bloquea" if f["id"] in blocking else "advertencia"))
            L.append(f"| {code(f['id'])} | {md(f['severity'])} | {md(f['confidence'])} | {md(f['origin'])} | {code(f['control_id'])} | "
                     f"{code(loc)} | {md(f['title'])} | {md(st)} |")
        L += [""]
        for f in fs:
            L += [f"### {code(f['id'])} — {md(f['title'])}", "",
                  f"- Control: {code(f['control_id'])} · severidad **{md(f['severity'])}** · confianza {md(f['confidence'])} · origen **{md(f['origin'])}**"
                  + (f" ({md(f['tool'])})" if f.get("tool") else "") + f" · baseline: {md(f['baseline_status'])}",
                  f"- Ubicación: {code((f['file'] or 'proyecto') + (':' + str(f['start_line']) if f.get('start_line') else ''))}",
                  f"- Descripción: {md(f['description'])}"]
            if f["evidence"]:
                L.append(f"- Evidencia: {md(f['evidence'])}")
            if f["risk"]:
                L.append(f"- Riesgo: {md(f['risk'])}")
            if f["remediation"]:
                L.append(f"- Remediación: {md(f['remediation'])}")
            if f["mappings"]:
                L.append("- Mappings: " + "; ".join(
                    f"{md(m['framework'])} {md(m['ref'])} ({'exacta' if m['type'] == 'exact' else 'temática'}{'' if m['validated'] else ', no validada'})"
                    for m in f["mappings"][:6]))
            L.append("")

    L += ["## Controles", "", "| Control | Estado | Fuente | Motivo |", "|---|---|---|---|"]
    for c in r["controls"]:
        tag = " (soporte)" if c.get("supporting") else ""
        L.append(f"| {code(c['control_id'])}{tag} {md(c['title'])} | {ICON[c['status']]} {c['status']} | {md(c['source'])} | {md(c['reason'])} |")
    L += [""]

    L += ["## Qué falta comprobar y cómo resolverlo", ""]
    pend = [c for c in r["controls"] if c["status"] in ("UNKNOWN", "NOT_RUN", "ERROR")]
    if not pend:
        L += ["No hay controles seleccionados sin verificar.", ""]
    else:
        for c in pend:
            hint = RESOLVE.get((c["method"], c["status"]), "Aporte la información faltante y repita la revisión.")
            if c["domain"] == "itgc" and "Alcance SOX" in c["reason"]:
                hint = "Defina project.sox_scope (yes/no) según la definición de alcance de la organización."
            L.append(f"- {ICON[c['status']]} {code(c['control_id'])} ({c['status']}): {md(hint)}")
        L += [""]

    L += ["## Scanners", ""]
    if not r["scanners"]:
        L += ["No se ejecutó ningún scanner en este comando.", ""]
    else:
        L += ["| Herramienta | Capacidad | Estado | Versión | Alcance | Duración | Notas |", "|---|---|---|---|---|---|---|"]
        for s_ in r["scanners"]:
            notes = "; ".join(s_.get("notes", []) + ([s_["error"]] if s_.get("error") else []))
            L.append(f"| {md(s_['tool'])} | {md(s_['capability'])} | **{md(s_['status'])}** | {md(s_.get('version') or '—')} | "
                     f"{md(s_.get('scope') or '—')} | {s_.get('duration_seconds', 0)}s | {md(notes)} |")
        L += [""]

    ev = r["evidence"]
    L += ["## Evidencia importada", ""]
    if not ev["provided"]:
        L += ["No se aportó evidencia de proceso (PR/CI/despliegue)."]
    else:
        L += [md(ev.get("authenticity_note", "")), "", "| ID | Tipo | Procedencia | Validación | Motivo |", "|---|---|---|---|---|"]
        for i in ev["items"]:
            v = i["validation"]
            decl = f" (declarada {i['provenance_declared']})" if i.get("provenance_declared") != i["provenance"] else ""
            L.append(f"| {code(i['id'])} | {md(i['type'])} | {md(i['provenance'])}{md(decl)} | {md(v['status'])} | {md(v['reason'] or '—')} |")
    L += [""]

    ar = r["agent_review"]
    L += ["## Revisión del agente", ""]
    if not ar["provided"]:
        L += ["No se importó una revisión del agente: los controles de método `agent` quedan `NOT_RUN`."]
    elif not ar["accepted"]:
        L += [f"Revisión recibida y **rechazada**: {md(ar.get('reason', ''))}"]
    else:
        L += [f"Revisión aceptada (procedencia `agent_review`, no verificada de forma independiente). Cliente: {md(ar.get('reviewer', {}).get('client', ''))}."]
        for rej in ar.get("rejected_entries", []):
            L.append(f"- Entrada rechazada {code(rej['ref'])}: {md(rej['reason'])}")
    L += [""]

    if r.get("exceptions"):
        L += ["## Excepciones aplicadas", ""] + [
            f"- {code(e['id'])} · responsable {md(e['owner'])} · vence {md(e['expires'])} · {md(e['reason'])}" for e in r["exceptions"]] + [""]

    L += ["## Limitaciones y advertencias", ""]
    L += [f"- {md(x)}" for x in r["limitations"]] + [f"- ⚠️ {md(x)}" for x in r["warnings"]] + [""]
    L += ["## Configuración efectiva", "", "```json", json.dumps(r["config"]["effective"], indent=2, ensure_ascii=False).replace("```", "'''"), "```", ""]
    return final_scrub("\n".join(L))


# ------------------------------------------------------------------ persistencia

def write_run(report: Dict[str, Any], out_root: Path, inventory: Dict[str, Any], tool_outputs: List[Dict[str, Any]]) -> Path:
    run_dir = out_root / report["run_id"]
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise ScError(f"Ya existe {run_dir}; los reportes nunca se sobrescriben.") from exc
    except OSError as exc:
        raise ScError(f"No se pudo crear el directorio de salida {run_dir}: {exc}") from exc
    files: Dict[str, str] = {}
    report["snapshot"]["inventory_file"] = "inventory.json"
    files["report.json"] = final_scrub(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)) + "\n"
    files["report.md"] = render_markdown(report)
    from .presentation import render_html, render_remediation   # import tardío: presentation usa helpers de este módulo
    files["remediation.md"] = render_remediation(report)
    files["presentation.html"] = render_html(report)
    files["inventory.json"] = json.dumps({"snapshot_hash": report["snapshot"]["snapshot_hash"],
                                          "files": inventory["files"], "skipped": inventory["skipped"],
                                          "include": inventory["include"], "exclude": inventory["exclude"]},
                                         ensure_ascii=False) + "\n"
    if tool_outputs:
        (run_dir / "tool-output").mkdir()
        for t in tool_outputs:
            files[f"tool-output/{t['tool']}.json"] = final_scrub(json.dumps(t, indent=2, ensure_ascii=False)) + "\n"
    sums = []
    for name, content in files.items():
        data = content.encode("utf-8", "surrogateescape")
        (run_dir / name).write_bytes(data)
        sums.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    (run_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    # copias de conveniencia con nombre estable (se actualizan en cada ejecución del mismo comando)
    for src, dst in (("presentation.html", f"latest-{report['command']}-presentation.html"),
                     ("remediation.md", f"latest-{report['command']}-remediation.md")):
        (out_root / dst).write_bytes(files[src].encode("utf-8", "surrogateescape"))
    return run_dir


def load_run(run_dir: Path) -> Dict[str, Any]:
    rp = run_dir / "report.json"
    if not rp.is_file():
        raise ConfigError(f"No existe report.json en {run_dir}", "Indique el directorio de una ejecución (--run <dir>/<run-id>).")
    raw = rp.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise ConfigError(f"report.json inválido: {exc}") from exc
    errs = validate_report(data)
    if errs:
        raise ConfigError("report.json no cumple el schema:\n  - " + "\n  - ".join(errs[:10]))
    sums = run_dir / "SHA256SUMS"
    data["_integrity"] = "sin SHA256SUMS: no se puede comprobar si el reporte fue modificado"
    if sums.is_file():
        recorded = {l.split("  ", 1)[1]: l.split("  ", 1)[0] for l in sums.read_text().splitlines() if "  " in l}
        ok = recorded.get("report.json") == hashlib.sha256(raw).hexdigest()
        data["_integrity"] = ("coincide con SHA256SUMS (detecta cambios accidentales; no es una firma ni cadena de custodia)"
                              if ok else "NO COINCIDE con SHA256SUMS: el reporte fue modificado tras su generación")
    return data
