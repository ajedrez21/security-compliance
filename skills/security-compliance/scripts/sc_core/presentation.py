"""Salidas de presentación a partir de report.json: plan de remediación (Markdown) y presentación HTML.

* HTML autocontenido: sin JavaScript, sin recursos externos (CSP restrictiva), todo el texto escapado,
  gráficos en SVG/CSS. Claro/oscuro por prefers-color-scheme; imprimible.
* Nada de lo mostrado se recalcula: todo sale del reporte (no cambia conclusiones).
"""
from __future__ import annotations

import html
from collections import Counter, OrderedDict
from typing import Any, Dict, List

from .catalog import by_id
from .findings import SEV_RANK, SEVERITIES
from .redact import final_scrub
from .report import md, code

SEV_ES = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa"}
SEV_COLOR = {"critical": "var(--c-critical)", "high": "var(--c-high)", "medium": "var(--c-medium)",
             "low": "var(--c-low)", "info": "var(--c-info)"}
SEV_CRITERIA = {
    "critical": ("Explotable con impacto severo (ejecución de código, exposición masiva de datos, toma de control) y poco o ningún "
                 "requisito previo.", "Inmediata: corregir antes de seguir desplegando."),
    "high": ("Vulnerabilidad probable con impacto grave, o explotable por usuarios autenticados.", "Corta: planificar en el sprint actual."),
    "medium": ("Debilidad con impacto acotado o que requiere condiciones adicionales para explotarse.", "Media: planificar en el próximo ciclo."),
    "low": ("Mala práctica o riesgo menor sin explotación directa evidente.", "Baja: corregir cuando se toque el código."),
    "info": ("Observación sin riesgo directo; mejora o contexto.", "Opcional."),
}
STATUS_ES = {"PASS": "Cumple", "FAIL": "No cumple", "UNKNOWN": "Desconocido", "NOT_APPLICABLE": "No aplica",
             "NOT_RUN": "No ejecutado", "ERROR": "Error"}
STATUS_COLOR = {"PASS": "var(--ok)", "FAIL": "var(--c-critical)", "UNKNOWN": "var(--c-medium)",
                "NOT_APPLICABLE": "var(--muted)", "NOT_RUN": "var(--c-info)", "ERROR": "var(--c-high)"}
ORIGIN_ES = {"scanner": "scanner", "heuristic": "heurística (sin confirmar)", "local_observation": "observación local",
             "agent_review": "revisión del agente", "user_supplied": "aportada por el usuario", "provider_verified": "verificada por proveedor"}
FRAMEWORKS = OrderedDict([
    ("owasp_asvs", ("OWASP ASVS 5.0.0", "Estándar de verificación de seguridad de aplicaciones (niveles L1-L3). Las referencias "
                    "«exactas» se validaron contra los IDs oficiales; la relación con cada control es criterio propio. "
                    "Cubrir requisitos no equivale a certificar un nivel.")),
    ("iso27001", ("ISO/IEC 27001:2022 (Annex A)", "Controles de seguridad de la información. Los mappings son temáticos y "
                  "NO están validados contra el texto de la norma (de pago). No evalúa el sistema de gestión.")),
    ("sox_itgc", ("SOX / ITGC (ruleset propio)", "Controles generales de TI de apoyo a revisiones SOX. Es un ruleset propio, "
                  "no un mandato legal literal; depende del alcance y de las políticas de la organización.")),
])
EVIDENCE_NOTE = {"scanner": "Detectado por una herramienta automática (versión y alcance en el reporte).",
                 "agent_review": "Análisis del agente de IA con flujo documentado; no verificado de forma independiente."}


def _sorted_findings(r):
    return sorted(r["findings"], key=lambda f: (SEV_RANK[f["severity"]], f["control_id"], f["file"] or "", f["id"]))


def _counted(r):
    """Hallazgos que cuentan para el resumen: en alcance y sin excepción."""
    return [f for f in _sorted_findings(r) if f["in_scope"]]


def _map_chips(f) -> List[str]:
    out = []
    for m in f["mappings"]:
        fw = FRAMEWORKS.get(m["framework"], (m["framework"], ""))[0]
        tag = "exacta" if m["type"] == "exact" else "temática"
        if not m["validated"]:
            tag += ", no validada"
        out.append(f"{fw} {m['ref']} ({tag})")
    return out


def _next_steps(r) -> List[str]:
    pend = [c for c in r["controls"] if c["status"] in ("UNKNOWN", "NOT_RUN", "ERROR")]
    kinds = Counter(c["method"] for c in pend)
    out = []
    if kinds.get("agent"):
        out.append(f"{kinds['agent']} control(es) de revisión del agente sin verificar: pedir al agente que los revise y reimportar con --review.")
    if kinds.get("scanner"):
        out.append("Scanners faltantes, con error o sin permiso de red: ver la sección de scanners (se instalan por fuera del skill).")
    if kinds.get("evidence"):
        out.append("Controles de proceso (SOX/ISO) sin evidencia: aportar evidencia de PR/CI con --evidence y definir project.sox_scope.")
    return out


# ------------------------------------------------------------------ progreso

def _line(b) -> str:
    loc = (b["file"] or "proyecto") + (f":{b['start_line']}" if b.get("start_line") else "")
    return f"{md(SEV_ES[b['severity']])} · {md(b['title'])} — {code(loc)} ({code(b['control_id'])})"


def _progress_md(r) -> List[str]:
    p = r.get("progress") or {"has_previous": False}
    L: List[str] = ["## Progreso desde la revisión anterior", ""]
    if not p["has_previous"]:
        return L + ["Es la primera revisión de este comando en esta carpeta de reportes: no hay comparación todavía. "
                    "Cuando corrijas problemas, repetí el mismo comando y este plan se actualizará solo (resueltos, nuevos y pendientes).", ""]
    tot_b, tot_a = sum(p["counts_before"].values()), sum(p["counts_after"].values())
    L += [f"Comparado con {code(p['previous_run_id'])} ({md(p['previous_generated_at'])}): gate `{p['gate_before']}` → `{p['gate_after']}`.", "",
          f"- Problemas: **{tot_b} → {tot_a}** · resueltos **{len(p['resolved'])}** · persisten **{len(p['persistent'])}** · "
          f"nuevos **{len(p['new'])}** · sin reverificar **{len(p['not_reverified'])}**", ""]
    if p["resolved"]:
        L += ["### ✅ Resueltos (el control se reverificó y el hallazgo ya no aparece)", ""] + [f"- [x] {_line(b)}" for b in p["resolved"]] + [""]
    if p["new"]:
        L += ["### 🆕 Nuevos desde la revisión anterior", ""] + [f"- [ ] {_line(b)}" for b in p["new"]] + [""]
    if p["not_reverified"]:
        L += ["### ❓ Sin reverificar (no se puede afirmar que se corrigieron)", "",
              "Su control no se pudo evaluar en esta ejecución (por ejemplo: el código cambió y falta repetir la revisión del agente, o falta un scanner).", ""]
        L += [f"- [ ] {_line(b)} — control ahora: {md(b['control_status_now'])}" for b in p["not_reverified"]] + [""]
    ch = [c for c in p["control_changes"] if c["to"] == "PASS" or c["from"] == "PASS"]
    if ch:
        L += ["### Controles que cambiaron de estado", ""] + [f"- {code(c['control_id'])}: {c['from']} → {c['to']}" for c in ch[:40]] + [""]
    return L


# ------------------------------------------------------------------ plan de remediación (Markdown)

def render_remediation(r: Dict[str, Any]) -> str:
    fs = _counted(r)
    g = r["gate"]
    L: List[str] = [f"# Plan de remediación — {md(r['project']['name'])}", "",
                    f"> {md(r['disclaimer'])}", "",
                    f"- **Run:** {code(r['run_id'])} · **Comando:** `{r['command']}` · **Fecha (UTC):** {md(r['generated_at'])}",
                    f"- **Resultado del gate:** `{g['status']}` · **Snapshot:** {code(r['snapshot']['snapshot_hash'][:23])}…",
                    f"- **Problemas a corregir:** {len(fs)} " + "(" + ", ".join(
                        f"{SEV_ES[s]}: {n}" for s in SEVERITIES for n in [sum(1 for f in fs if f['severity'] == s)] if n) + ")", ""]
    L += ["## Cómo se priorizó", "",
          "Se ordena por severidad (impacto y exposición), luego por confianza. Marcá cada casilla al corregir y repetí la revisión para confirmar.", "",
          "| Severidad | Criterio | Prioridad sugerida |", "|---|---|---|"]
    for s in SEVERITIES:
        L.append(f"| {SEV_ES[s]} | {md(SEV_CRITERIA[s][0])} | {md(SEV_CRITERIA[s][1])} |")
    L += ["", "_Las prioridades son una sugerencia del skill; la política de plazos la define la organización._", ""]

    L += _progress_md(r)
    blocking = set(g["blocking_findings"])
    L += ["## Problemas a corregir", ""]
    if not fs:
        L += ["No hay hallazgos registrados en esta ejecución. Esto **no** implica ausencia de vulnerabilidades: ver «Pendiente de verificar».", ""]
    n = 0
    for sev in SEVERITIES:
        group = [f for f in fs if f["severity"] == sev]
        if not group:
            continue
        L += [f"### {SEV_ES[sev]} ({len(group)})", ""]
        for f in group:
            n += 1
            loc = (f["file"] or "proyecto") + (f":{f['start_line']}" if f.get("start_line") else "")
            flags = []
            if f["id"] in blocking:
                flags.append("**bloquea el gate**")
            if f["origin"] == "heuristic":
                flags.append("heurística: confirmar antes de corregir")
            if f["confidence"] == "low":
                flags.append("confianza baja")
            L += [f"- [ ] **{n}. {md(f['title'])}** — {code(loc)}" + (f" ({'; '.join(flags)})" if flags else ""),
                  f"  - **Qué pasa:** {md(f['description'])}"]
            if f["risk"]:
                L.append(f"  - **Riesgo:** {md(f['risk'])}")
            L.append(f"  - **Qué hacer:** {md(f['remediation'] or 'Revisar el hallazgo y corregir el patrón inseguro.')}")
            chips = _map_chips(f)
            if chips:
                L.append("  - **Normas:** " + "; ".join(md(c) for c in chips[:6]))
            L.append(f"  - **Control:** {code(f['control_id'])} · **Origen:** {md(ORIGIN_ES.get(f['origin'], f['origin']))} · **ID:** {code(f['id'])}")
            L.append("")

    pend = [c for c in r["controls"] if c["status"] in ("UNKNOWN", "NOT_RUN", "ERROR") and not c.get("supporting")]
    L += ["## Pendiente de verificar (no son defectos confirmados)", "",
          "Estos controles no se pudieron comprobar. Hasta resolverlos, no hay garantía sobre ellos.", ""]
    if not pend:
        L += ["Todos los controles seleccionados se verificaron.", ""]
    else:
        L += [f"- [ ] {code(c['control_id'])} {md(c['title'])} — {STATUS_ES[c['status']]}: {md(c['reason'])}" for c in pend[:80]]
        if len(pend) > 80:
            L.append(f"- … y {len(pend) - 80} más (ver report.json)")
        L.append("")
    steps = _next_steps(r)
    if steps:
        L += ["## Próximos pasos para completar la revisión", ""] + [f"1. {md(s)}" for s in steps] + [""]
    L += ["## Limitaciones", ""] + [f"- {md(x)}" for x in r["limitations"]] + [f"- ⚠️ {md(x)}" for x in r["warnings"]] + [""]
    return final_scrub("\n".join(L))


# ------------------------------------------------------------------ HTML

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b2430;--muted:#667085;--line:#e3e7ee;--accent:#2f5bea;--ok:#1a9b5c;
--c-critical:#c4262e;--c-high:#e06c1a;--c-medium:#d9a400;--c-low:#2f7fd1;--c-info:#7a8699;--chip:#eef1f6;--on:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#10141b;--card:#181e28;--text:#e8ecf3;--muted:#98a2b3;--line:#2a3340;--accent:#7b9bff;--ok:#38c585;
--c-critical:#ff6b72;--c-high:#ff9a4d;--c-medium:#f2c94c;--c-low:#6aaef0;--c-info:#98a2b3;--chip:#232b38;--on:#10141b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}h3{font-size:16px;margin:0}
.sub{color:var(--muted);font-size:13px}.notice{background:var(--chip);border-left:4px solid var(--c-medium);padding:10px 14px;border-radius:6px;margin:16px 0;font-size:13px}
.grid{display:grid;gap:14px}.kpis{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}.two{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.kpi b{display:block;font-size:30px;line-height:1.1}.kpi span{color:var(--muted);font-size:13px}
.gate{display:inline-block;padding:4px 12px;border-radius:999px;color:var(--on);font-weight:700;font-size:14px}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;color:var(--on);font-size:12px;font-weight:600}
.chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 8px;font-size:12px;margin:2px 4px 2px 0}
.chip.warn{border:1px dashed var(--c-medium)}.chip.ok{border:1px solid var(--ok)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
.donut{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.donut svg{width:170px;height:170px;flex:none}
.legend div{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:14px}.dot{width:12px;height:12px;border-radius:3px;display:inline-block}
.stack{display:flex;height:26px;border-radius:7px;overflow:hidden;margin:10px 0}.stack span{display:block;height:100%}
.bar{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:13px}.bar i{display:block;height:12px;border-radius:4px;min-width:3px}.bar em{font-style:normal;width:110px;flex:none;color:var(--muted)}
details.f{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--sev);border-radius:10px;margin:10px 0;padding:0}
details.f>summary{cursor:pointer;padding:12px 14px;list-style:none;display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}
details.f>summary::-webkit-details-marker{display:none}.fb{padding:0 14px 14px;font-size:14px}.fb p{margin:6px 0}.fb b{color:var(--muted);font-weight:600}
code{background:var(--chip);border-radius:4px;padding:0 5px;font-size:13px;word-break:break-all}
footer{margin-top:40px;color:var(--muted);font-size:12px}
@media print{body{background:#fff}details.f>.fb{display:block}.card{break-inside:avoid}}
"""


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _donut(counts: Dict[str, int]) -> str:
    total = sum(counts.values())
    if not total:
        return ('<svg viewBox="0 0 42 42" role="img" aria-label="Sin hallazgos"><circle cx="21" cy="21" r="15.9155" fill="none" '
                'stroke="var(--line)" stroke-width="6"/><text x="21" y="23" text-anchor="middle" font-size="7" fill="currentColor">0</text></svg>')
    parts, offset = [], 25.0   # arranca a las 12 h
    for s in SEVERITIES:
        n = counts.get(s, 0)
        if not n:
            continue
        pct = n * 100.0 / total
        parts.append(f'<circle cx="21" cy="21" r="15.9155" fill="none" stroke="{SEV_COLOR[s]}" stroke-width="6" '
                     f'stroke-dasharray="{pct:.3f} {100 - pct:.3f}" stroke-dashoffset="{offset:.3f}"><title>{_e(SEV_ES[s])}: {n}</title></circle>')
        offset -= pct
    return (f'<svg viewBox="0 0 42 42" role="img" aria-label="Hallazgos por severidad">{"".join(parts)}'
            f'<text x="21" y="22.5" text-anchor="middle" font-size="8" font-weight="700" fill="currentColor">{total}</text>'
            '<text x="21" y="28" text-anchor="middle" font-size="3" fill="currentColor" opacity=".7">hallazgos</text></svg>')


def _trend_svg(points: List[Dict[str, Any]]) -> str:
    if len(points) < 2:
        return ""
    W, Hh, pad = 520, 160, 28
    totals = [sum(x["findings"].values()) for x in points]
    ch = [x["findings"].get("critical", 0) + x["findings"].get("high", 0) for x in points]
    mx = max(max(totals), 1)
    def xy(i, v):
        return pad + i * (W - 2 * pad) / (len(points) - 1), Hh - pad - v * (Hh - 2 * pad) / mx
    def line(vals, color):
        pts = " ".join(f"{xy(i, v)[0]:.1f},{xy(i, v)[1]:.1f}" for i, v in enumerate(vals))
        dots = "".join(f'<circle cx="{xy(i, v)[0]:.1f}" cy="{xy(i, v)[1]:.1f}" r="3.5" fill="{color}"><title>{_e(points[i]["generated_at"][:16])}: {v}</title></circle>' for i, v in enumerate(vals))
        return f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="2.5"/>{dots}'
    return (f'<svg viewBox="0 0 {W} {Hh}" role="img" aria-label="Evolución de hallazgos" style="width:100%;max-width:560px">'
            f'<line x1="{pad}" y1="{Hh - pad}" x2="{W - pad}" y2="{Hh - pad}" stroke="var(--line)"/>'
            f'{line(totals, "var(--accent)")}{line(ch, "var(--c-critical)")}'
            f'<text x="{pad}" y="14" font-size="11" fill="currentColor">máx. {mx}</text></svg>'
            '<div class="legend"><div><span class="dot" style="background:var(--accent)"></span>Todos los problemas</div>'
            '<div><span class="dot" style="background:var(--c-critical)"></span>Críticos + altos</div></div>')


def _progress_html(r: Dict[str, Any], sev_counts) -> str:
    p = r.get("progress") or {"has_previous": False}
    hist = list(r.get("history") or [])
    cur = {"run_id": r["run_id"], "generated_at": r["generated_at"], "gate": r["gate"]["status"],
           "findings": {s: sev_counts.get(s, 0) for s in SEVERITIES}, "controls": r["coverage"]["by_status"]}
    out = ["<h2>Progreso</h2>"]
    if not p["has_previous"]:
        out.append("<div class=\"card\">Primera revisión de este comando en esta carpeta de reportes. Al corregir problemas y repetir el mismo comando, "
                   "esta sección mostrará resueltos, nuevos, pendientes y la evolución.</div>")
        return "".join(out)
    tb, ta = sum(p["counts_before"].values()), sum(p["counts_after"].values())
    out.append("<div class=\"grid kpis\">"
               f"<div class=\"card kpi\"><b>{tb} → {ta}</b><span>problemas (anterior → actual)</span></div>"
               f"<div class=\"card kpi\"><b style=\"color:var(--ok)\">{len(p['resolved'])}</b><span>resueltos</span></div>"
               f"<div class=\"card kpi\"><b>{len(p['persistent'])}</b><span>persisten</span></div>"
               f"<div class=\"card kpi\"><b style=\"color:var(--c-high)\">{len(p['new'])}</b><span>nuevos</span></div>"
               f"<div class=\"card kpi\"><b style=\"color:var(--c-medium)\">{len(p['not_reverified'])}</b><span>sin reverificar</span></div></div>")
    out.append(f"<p class=\"sub\">Comparado con {_e(p['previous_run_id'])} ({_e(p['previous_generated_at'])}). Gate: {_e(p['gate_before'])} → {_e(p['gate_after'])}. {_e(p['note'])}</p>")
    def lst(title, items, extra=""):
        if not items:
            return ""
        rows = []
        for b in items:
            loc = (b["file"] or "proyecto") + (":" + str(b["start_line"]) if b.get("start_line") else "")
            now = ""
            if extra and b.get("control_status_now"):
                now = ' <span class="sub">control ahora: ' + _e(b["control_status_now"]) + "</span>"
            rows.append(f'<li><span class="badge" style="background:{SEV_COLOR[b["severity"]]}">{_e(SEV_ES[b["severity"]])}</span> '
                        f'{_e(b["title"])} <code>{_e(loc)}</code> <span class="chip">{_e(b["control_id"])}</span>{now}</li>')
        return f'<div class="card" style="margin-top:10px"><h3>{title} ({len(items)})</h3><ul>' + "".join(rows) + "</ul></div>"
    out.append(lst("✅ Resueltos", p["resolved"]))
    out.append(lst("🆕 Nuevos", p["new"]))
    out.append(lst("❓ Sin reverificar", p["not_reverified"], "x"))
    trend = _trend_svg(hist + [cur])
    if trend:
        out.append(f"<div class=\"card\" style=\"margin-top:10px\"><h3>Evolución entre revisiones ({len(hist) + 1})</h3>{trend}</div>")
    return "".join(out)


def render_html(r: Dict[str, Any]) -> str:
    fs = _counted(r)
    g = r["gate"]
    sev_counts = Counter(f["severity"] for f in fs)
    st_counts = r["coverage"]["by_status"]
    total_ctl = max(r["coverage"]["controls_selected"], 1)
    cat = by_id()
    gate_color = {"PASS": "var(--ok)", "PASS_WITH_WARNINGS": "var(--c-medium)", "BLOCKED": "var(--c-critical)", "INCOMPLETE": "var(--c-high)"}[g["status"]]
    gate_es = {"PASS": "Aprobado", "PASS_WITH_WARNINGS": "Aprobado con advertencias", "BLOCKED": "Bloqueado", "INCOMPLETE": "Incompleto"}[g["status"]]
    blocking = set(g["blocking_findings"])
    H: List[str] = []
    a = H.append
    a("<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">")
    a("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">")
    a("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    a(f"<title>Revisión de seguridad — {_e(r['project']['name'])}</title><style>{CSS}</style></head><body><div class=\"wrap\">")
    a(f"<h1>Revisión de controles técnicos — {_e(r['project']['name'])}</h1>")
    a(f"<div class=\"sub\">Run {_e(r['run_id'])} · comando {_e(r['command'])} · {_e(r['generated_at'])} · skill {_e(r['skill']['version'])} · "
      f"catálogo {_e(r['catalog']['version'])}</div>")
    a(f"<div class=\"notice\">{_e(r['disclaimer'])}</div>")

    a("<h2>Resumen</h2><div class=\"grid kpis\">")
    a(f"<div class=\"card kpi\"><span>Resultado del gate</span><b><span class=\"gate\" style=\"background:{gate_color}\">{_e(gate_es)}</span></b>"
      f"<span>{_e(g['status'])} · modo {_e(g['mode'])}</span></div>")
    a(f"<div class=\"card kpi\"><b>{len(fs)}</b><span>problemas a corregir</span></div>")
    a(f"<div class=\"card kpi\"><b style=\"color:var(--c-critical)\">{sev_counts.get('critical', 0) + sev_counts.get('high', 0)}</b><span>críticos + altos</span></div>")
    a(f"<div class=\"card kpi\"><b>{st_counts.get('PASS', 0)}/{r['coverage']['controls_selected']}</b><span>controles que cumplen</span></div>")
    pend_n = st_counts.get("UNKNOWN", 0) + st_counts.get("NOT_RUN", 0) + st_counts.get("ERROR", 0)
    a(f"<div class=\"card kpi\"><b style=\"color:var(--c-medium)\">{pend_n}</b><span>controles sin verificar</span></div>")
    a(f"<div class=\"card kpi\"><b>{r['snapshot']['file_count']}</b><span>archivos en alcance</span></div></div>")
    if g["reasons"]:
        a("<div class=\"card\" style=\"margin-top:14px\"><h3>Motivos del resultado</h3><ul>" + "".join(f"<li>{_e(x)}</li>" for x in g["reasons"]) + "</ul></div>")

    a("<h2>Gráficos</h2><div class=\"grid two\">")
    a("<div class=\"card\"><h3>Hallazgos por severidad</h3><div class=\"donut\">" + _donut(sev_counts) + "<div class=\"legend\">" +
      "".join(f"<div><span class=\"dot\" style=\"background:{SEV_COLOR[s]}\"></span>{_e(SEV_ES[s])}: <b>{sev_counts.get(s, 0)}</b></div>" for s in SEVERITIES) + "</div></div></div>")
    a("<div class=\"card\"><h3>Estado de los controles</h3><div class=\"stack\">" +
      "".join(f"<span style=\"width:{st_counts.get(s, 0) * 100.0 / total_ctl:.2f}%;background:{STATUS_COLOR[s]}\" title=\"{_e(STATUS_ES[s])}: {st_counts.get(s, 0)}\"></span>" for s in STATUS_ES) + "</div><div class=\"legend\">" +
      "".join(f"<div><span class=\"dot\" style=\"background:{STATUS_COLOR[s]}\"></span>{_e(STATUS_ES[s])}: <b>{st_counts.get(s, 0)}</b></div>" for s in STATUS_ES) + "</div></div>")
    by_dom: Dict[str, Counter] = {}
    for c in r["controls"]:
        by_dom.setdefault(c["domain"], Counter())[c["status"]] += 1
    dom_es = {"security": "Seguridad de aplicación", "itgc": "SOX / ITGC", "iso": "ISO/IEC 27001"}
    a("<div class=\"card\"><h3>Controles por dominio</h3>")
    for d, cnt in by_dom.items():
        tot = sum(cnt.values())
        a(f"<div class=\"sub\" style=\"margin-top:8px\">{_e(dom_es.get(d, d))} ({tot})</div><div class=\"stack\">" +
          "".join(f"<span style=\"width:{cnt[s] * 100.0 / tot:.2f}%;background:{STATUS_COLOR[s]}\" title=\"{_e(STATUS_ES[s])}: {cnt[s]}\"></span>" for s in STATUS_ES if cnt[s]) + "</div>")
    a("</div>")
    top = Counter(f["control_id"] for f in fs).most_common(8)
    a("<div class=\"card\"><h3>Controles con más hallazgos</h3>")
    if not top:
        a("<div class=\"sub\">Sin hallazgos.</div>")
    mx = top[0][1] if top else 1
    for cid, n in top:
        a(f"<div class=\"bar\"><em>{_e(cid)}</em><i style=\"width:{n * 100.0 / mx * 0.6:.1f}%;background:var(--accent)\"></i><b>{n}</b></div>")
    a("</div></div>")

    a(_progress_html(r, sev_counts))
    a("<h2>Niveles de severidad y criterios</h2><div class=\"card\"><table><tr><th>Severidad</th><th>Criterio</th><th>Prioridad sugerida</th><th>Hallazgos</th></tr>")
    for s in SEVERITIES:
        a(f"<tr><td><span class=\"badge\" style=\"background:{SEV_COLOR[s]}\">{_e(SEV_ES[s])}</span></td><td>{_e(SEV_CRITERIA[s][0])}</td>"
          f"<td>{_e(SEV_CRITERIA[s][1])}</td><td><b>{sev_counts.get(s, 0)}</b></td></tr>")
    a("</table><p class=\"sub\">La severidad se deriva del impacto y la exposición, no del nombre de una variable; no se asignan CVSS ni CVE sin una fuente identificable. "
      "<b>Confianza</b> (alta/media/baja) indica cuán seguro es el hallazgo; <b>origen</b> indica quién lo detectó (scanner, revisión del agente, observación local o heurística sin confirmar). "
      "Bloquean el gate los hallazgos con severidad en el umbral (" + _e(", ".join(g["policy"]["block_severities"])) + ") y confianza no baja. Las prioridades son una sugerencia: los plazos los define la organización.</p></div>")

    a("<h2>Normas y marcos</h2><div class=\"grid two\">")
    ctl_by_fw: Dict[str, List[Dict[str, Any]]] = {k: [] for k in FRAMEWORKS}
    for c in r["controls"]:
        fws = {m["framework"] for m in cat[c["control_id"]]["mappings"]} | set(cat[c["control_id"]]["frameworks"])
        for fw in FRAMEWORKS:
            if fw in fws:
                ctl_by_fw[fw].append(c)
    for fw, (name, desc) in FRAMEWORKS.items():
        cs = ctl_by_fw[fw]
        cnt = Counter(c["status"] for c in cs)
        refs = {m["ref"] for f in fs for m in f["mappings"] if m["framework"] == fw}
        a(f"<div class=\"card\"><h3>{_e(name)}</h3><p class=\"sub\">{_e(desc)}</p>")
        a(f"<p>Controles relacionados: <b>{len(cs)}</b> · " + " · ".join(f"{_e(STATUS_ES[s])}: <b>{cnt[s]}</b>" for s in STATUS_ES if cnt[s]) + "</p>")
        a(f"<p>Referencias con hallazgos: " + ("".join(f"<span class=\"chip\">{_e(x)}</span>" for x in sorted(refs)[:24]) or "<span class=\"sub\">ninguna</span>") + "</p></div>")
    a("</div>")
    asvs = r["coverage"]["asvs"]
    a(f"<p class=\"sub\">{_e(asvs['baseline'])}: {asvs['requirements_referenced']} requisitos referenciados por los controles seleccionados "
      f"({asvs['requirements_referenced_within_target']} de {asvs['requirements_in_target_level']} dentro del nivel objetivo {asvs['target_level']}). {_e(asvs['statement'])}</p>")

    a("<h2>Problemas a corregir</h2>")
    if not fs:
        a("<div class=\"card\">No hay hallazgos registrados. Esto no implica ausencia de vulnerabilidades: revisá los controles sin verificar.</div>")
    for f in fs:
        loc = (f["file"] or "proyecto") + (f":{f['start_line']}" if f.get("start_line") else "")
        status = "Bloquea el gate" if f["id"] in blocking else ("Excepción " + f["exception"]["id"] if f.get("exception") else "No bloqueante")
        a(f"<details class=\"f\" style=\"--sev:{SEV_COLOR[f['severity']]}\"{' open' if f['severity'] in ('critical', 'high') else ''}><summary>"
          f"<span class=\"badge\" style=\"background:{SEV_COLOR[f['severity']]}\">{_e(SEV_ES[f['severity']])}</span><b>{_e(f['title'])}</b>"
          f"<code>{_e(loc)}</code><span class=\"chip\">{_e(f['control_id'])}</span><span class=\"chip\">{_e(ORIGIN_ES.get(f['origin'], f['origin']))}</span></summary><div class=\"fb\">")
        desc, _, flow = f["description"].partition("\nFlujo: ")
        a(f"<p><b>Qué pasa:</b> {_e(desc)}</p>")
        if flow:
            a(f"<p><b>Flujo:</b> {_e(flow)}</p>")
        if f["risk"]:
            a(f"<p><b>Riesgo:</b> {_e(f['risk'])}</p>")
        a(f"<p><b>Qué hacer:</b> {_e(f['remediation'] or 'Revisar el hallazgo y corregir el patrón inseguro.')}</p>")
        if f["evidence"]:
            a(f"<p><b>Evidencia:</b> {_e(f['evidence'])}</p>")
        a(f"<p><b>Confianza:</b> {_e(f['confidence'])} · <b>Estado:</b> {_e(status)} · <b>Línea base:</b> {_e(f['baseline_status'])} · <b>ID:</b> <code>{_e(f['id'])}</code>"
          + (f"<br><span class=\"sub\">{_e(EVIDENCE_NOTE[f['origin']])}</span>" if f["origin"] in EVIDENCE_NOTE else "") + "</p>")
        if f["mappings"]:
            a("<p><b>Normas:</b> " + "".join(
                f"<span class=\"chip {'ok' if m['type'] == 'exact' and m['validated'] else 'warn'}\">{_e(FRAMEWORKS.get(m['framework'], (m['framework'],))[0])} {_e(m['ref'])} "
                f"({'exacta' if m['type'] == 'exact' else 'temática'}{'' if m['validated'] else ', no validada'})</span>" for m in f["mappings"][:8]) + "</p>")
        a("</div></details>")

    a("<h2>Controles</h2><div class=\"card\"><table><tr><th>Control</th><th>Estado</th><th>Fuente</th><th>Motivo</th></tr>")
    for c in r["controls"]:
        sup = ' <span class="sub">(soporte)</span>' if c.get("supporting") else ""
        a(f"<tr><td><code>{_e(c['control_id'])}</code> {_e(c['title'])}{sup}</td>"
          f"<td><span class=\"badge\" style=\"background:{STATUS_COLOR[c['status']]}\">{_e(STATUS_ES[c['status']])}</span></td><td>{_e(c['source'])}</td><td>{_e(c['reason'])}</td></tr>")
    a("</table></div>")

    a("<h2>Qué falta comprobar</h2><div class=\"card\">")
    steps = _next_steps(r)
    a(("<ul>" + "".join(f"<li>{_e(s)}</li>" for s in steps) + "</ul>") if steps else "Todos los controles seleccionados se verificaron.")
    a("</div><h2>Scanners</h2><div class=\"card\">")
    if r["scanners"]:
        a("<table><tr><th>Herramienta</th><th>Capacidad</th><th>Estado</th><th>Versión</th><th>Alcance</th></tr>" + "".join(
            f"<tr><td>{_e(s['tool'])}</td><td>{_e(s['capability'])}</td><td><b>{_e(s['status'])}</b></td><td>{_e(s.get('version') or '—')}</td><td>{_e(s.get('scope') or '—')}</td></tr>" for s in r["scanners"]) + "</table>")
    else:
        a("No se ejecutó ningún scanner en este comando.")
    a("</div><h2>Limitaciones y advertencias</h2><div class=\"card\"><ul>" + "".join(f"<li>{_e(x)}</li>" for x in r["limitations"]) +
      "".join(f"<li>⚠️ {_e(x)}</li>" for x in r["warnings"]) + "</ul></div>")
    a(f"<footer>Snapshot {_e(r['snapshot']['snapshot_hash'])} · configuración {_e(r['config']['hash'])} ({_e(r['config']['policy_source'])}). "
      "Documento generado automáticamente desde report.json; no constituye una certificación.</footer></div></body></html>")
    return final_scrub("".join(H))
