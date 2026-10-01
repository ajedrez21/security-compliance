#!/usr/bin/env python3
"""security-compliance — runner determinístico (sin LLM, sin API keys, solo biblioteca estándar).

Uso rápido:
  python sc.py help
  python sc.py doctor --project .
  python sc.py diff --project . --base main
  python sc.py audit --project . --output ./audit-output
  python sc.py report --run ./audit-output/<run-id>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # no dejar __pycache__ dentro del directorio instalado

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sc_core import errors, skill_version  # noqa: E402
from sc_core.errors import ScError  # noqa: E402

REVIEW_COMMANDS = ["audit", "diff", "pr", "sox", "iso", "security", "secrets", "dependencies"]

HELP_SHORT = """security-compliance {version} — revisión de controles técnicos (seguridad, ISO/IEC 27001, ITGC/SOX, ASVS)

Comandos:  help  doctor  init  audit  diff  pr  sox  iso  security  secrets  dependencies  report
Ejemplos:  sc.py diff --project .            revisar cambios locales (staged, unstaged, nuevos)
           sc.py audit --project .           revisión completa del alcance
           sc.py sox --project . --evidence pr-evidence.json
           sc.py report --run <dir>/<run-id> mostrar una ejecución sin repetir escaneos
Ayuda completa: sc.py help all"""

HELP_FULL = """
COMANDOS
  help [all]      Esta ayuda. No requiere scanners.
  doctor          Diagnostica instalación, runtime, scanners, configuración y capacidades. No instala nada.
  init            Detecta el stack y genera .security-compliance.yml mínimo (no pisa uno existente).
  audit           Revisión completa del alcance (todos los marcos configurados).
  diff            Revisa cambios: staged + unstaged + untracked (+ commits desde el merge-base con --base).
  pr              Como diff + evidencia de PR/CI importada (--evidence); no consulta proveedores.
  sox             Controles ITGC de apoyo (aplicabilidad 'unknown' hasta definir project.sox_scope).
  iso             Controles técnicos relacionados con ISO/IEC 27001 (no evalúa el SGSI).
  security        Seguridad de aplicación con el catálogo y los mappings ASVS.
  secrets         Scanner de secretos disponible + heurísticas; nunca imprime valores.
  dependencies    Inventario de dependencias y vulnerabilidades (red solo si se permite).
  report          Muestra/exporta una ejecución existente (--format md|json|html|remediation) sin repetir escaneos ni cambiar conclusiones.

OPCIONES COMUNES
  --project DIR          Raíz del proyecto auditado (por defecto: directorio actual).
  --config FILE          Configuración alternativa (por defecto .security-compliance.yml, opcional).
  --output DIR           Directorio de reportes (por defecto: <proyecto>/.security-compliance/reports).
  --mode advisory|enforce  advisory informa sin impedir el trabajo; enforce habilita códigos de salida 1/3.
  --policy FILE          Política confiable externa al cambio (obligatoria en enforce salvo --allow-project-policy).
  --base REF             (diff/pr) base para el merge-base.   --head SHA  (pr) head SHA esperado.
  --evidence FILE        (repetible) evidencia de PR/CI/proceso (evidence.schema.json).
  --review FILE          Revisión estructurada del agente (review.schema.json); procedencia 'agent_review'.
  --json                 Imprime el reporte JSON en stdout (los archivos igualmente se guardan).
  --non-interactive      Sin preguntas. --timeout SEG  tiempo máximo por herramienta.

CÓDIGOS DE SALIDA
  0 aceptable según el modo · 1 bloqueo de política (enforce) · 2 error de configuración/runtime/argumentos ·
  3 evaluación incompleta (enforce). Precedencia: 2 > 1 > 3 > 0. En advisory el gate real queda en el JSON.

MODALIDADES
  Manual:   /security-compliance <comando>  (según el cliente) o lenguaje natural: "Usá el skill security-compliance ...".
  Asistida: el agente puede seleccionar el skill por contexto; no está garantizado.
  Obligatoria: solo mediante CI/branch protection/hooks configurados fuera del skill (ver docs).

LÍMITES
  No es una certificación ni una afirmación de cumplimiento SOX/ISO/ASVS. Ausencia de evidencia ≠ aprobación.
  Este CLI no llama modelos: el análisis contextual lo aporta el agente y se importa con --review.
"""


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--project", default=".", help="raíz del proyecto (default: .)")
    p.add_argument("--config", help="archivo de configuración alternativo")
    p.add_argument("--json", action="store_true", help="salida JSON en stdout")
    p.add_argument("--non-interactive", action="store_true", help="no hacer preguntas")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="sc.py", add_help=False)
    sub = ap.add_subparsers(dest="command")
    h = sub.add_parser("help", add_help=False)
    h.add_argument("topic", nargs="?")
    h.add_argument("--json", action="store_true")
    d = sub.add_parser("doctor", add_help=False)
    _common(d)
    i = sub.add_parser("init", add_help=False)
    _common(i)
    i.add_argument("--criticality", choices=["unknown", "low", "medium", "high", "critical"])
    for k in ("sox-scope", "contains-pii", "contains-financial-data"):
        i.add_argument(f"--{k}", choices=["unknown", "yes", "no"])
    i.add_argument("--update-gitignore", action="store_true")
    for name in REVIEW_COMMANDS:
        r = sub.add_parser(name, add_help=False)
        _common(r)
        r.add_argument("--output")
        r.add_argument("--mode", choices=["advisory", "enforce"])
        r.add_argument("--policy")
        r.add_argument("--allow-project-policy", action="store_true")
        r.add_argument("--timeout", type=int)
        r.add_argument("--review")
        r.add_argument("--evidence", action="append")
        r.add_argument("--base")
        r.add_argument("--head")
    rp = sub.add_parser("report", add_help=False)
    rp.add_argument("--run", required=True, help="directorio de la ejecución (<salida>/<run-id>)")
    rp.add_argument("--format", choices=["md", "json", "html", "remediation"], default="md")
    rp.add_argument("--out", help="escribir en este archivo en vez de stdout")
    rp.add_argument("--json", action="store_true")
    return ap


def _print(obj_or_text, as_json: bool) -> None:
    sys.stdout.write((json.dumps(obj_or_text, indent=2, ensure_ascii=False) if as_json else str(obj_or_text)) + "\n")


def cmd_help(args) -> int:
    short = HELP_SHORT.format(version=skill_version())
    if getattr(args, "json", False):
        _print({"version": skill_version(), "commands": ["help", "doctor", "init", *REVIEW_COMMANDS, "report"]}, True)
        return 0
    _print(short + (("\n" + HELP_FULL) if args.topic in ("all", "full") else ""), False)
    return 0


def cmd_noargs() -> int:
    from sc_core import gitutil
    _print(HELP_SHORT.format(version=skill_version()), False)
    cwd = Path.cwd()
    info = gitutil.git_info(cwd) if gitutil.git_available() else {"is_repo": False}
    if info.get("is_repo") and info.get("dirty"):
        _print("\nSugerencia: hay cambios locales → ejecute 'diff'. (No se inició ninguna revisión.)", False)
    else:
        _print("\nSugerencia: no hay cambios locales detectados → ejecute 'audit'. (No se inició ninguna revisión.)", False)
    return 0


def cmd_doctor(args) -> int:
    from sc_core import doctor
    r = doctor.run_doctor(Path(args.project).resolve())
    _print(r if args.json else doctor.format_doctor(r), args.json)
    return r["exit_code"]


def cmd_init(args) -> int:
    from sc_core import init_cmd
    r = init_cmd.run_init(Path(args.project).resolve(),
                          {"criticality": args.criticality, "sox_scope": args.sox_scope,
                           "contains_pii": args.contains_pii, "contains_financial_data": args.contains_financial_data},
                          interactive=not args.non_interactive, update_gitignore=args.update_gitignore)
    if args.json:
        _print(r, True)
    else:
        _print(r["message"] + (f"\n  Archivo: {r['path']}" if r["created"] else ""), False)
        if r["stacks"]:
            _print("  Stacks detectados: " + ", ".join(r["stacks"]), False)
        if r.get("gitignore"):
            _print("  " + r["gitignore"], False)
        if r["created"]:
            _print("  Siguiente paso: sc.py diff --project .  (o audit)", False)
    return 0


def cmd_review(args) -> int:
    from sc_core import commands
    res = commands.run_review(args.command, args)
    rep, run_dir = res["report"], res["run_dir"]
    if args.json:
        _print(rep, True)
    else:
        g = rep["gate"]
        _print(f"Gate: {g['status']} (modo {g['mode']}, salida {g['exit_code']})  ·  comando {rep['command']}  ·  run {rep['run_id']}", False)
        c = rep["coverage"]["by_status"]
        _print("Controles: " + ", ".join(f"{k}={v}" for k, v in c.items() if v) + f"  ·  hallazgos: {len(rep['findings'])}", False)
        for cap, st in rep["coverage"]["scanners"].items():
            _print(f"Scanner {cap}: {st}", False)
        for r_ in g["reasons"][:6]:
            _print(f"  - {r_}", False)
        top = [f for f in rep["findings"] if f["id"] in set(g["blocking_findings"])][:8]
        for f in top:
            _print(f"  ⛔ {f['severity']:<8} {f['control_id']} {f['file'] or ''}:{f['start_line'] or ''}  {f['title']}", False)
        _print(f"Reporte técnico:        {run_dir / 'report.md'}\nPlan de remediación:    {run_dir / 'remediation.md'}\n"
               f"Presentación (HTML):    {run_dir / 'presentation.html'}\nJSON:                   {run_dir / 'report.json'}", False)
        if res.get("gitignore_hint"):
            _print("Aviso: " + res["gitignore_hint"], False)
    return res["exit_code"]


def cmd_report(args) -> int:
    from sc_core import report as rep
    data = rep.load_run(Path(args.run).resolve())
    integrity = data.pop("_integrity")
    if args.format == "json" or args.json:
        text = json.dumps(data, indent=2, ensure_ascii=False)
    elif args.format == "html":
        from sc_core import presentation
        text = presentation.render_html(data)
    elif args.format == "remediation":
        from sc_core import presentation
        text = presentation.render_remediation(data)
    else:
        text = rep.render_markdown(data)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        sys.stderr.write(f"Escrito {args.out}\n")
    else:
        sys.stdout.write(text + "\n")
    sys.stderr.write(f"Integridad: {integrity}\n")
    return errors.EXIT_OK


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return cmd_noargs()
    if argv[0] in ("-h", "--help"):
        return cmd_help(argparse.Namespace(topic=None, json=False))
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse imprime su propio error; unificamos el código a 2
        return errors.EXIT_ERROR if exc.code not in (0, None) else 0
    try:
        if args.command == "help":
            return cmd_help(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "init":
            return cmd_init(args)
        if args.command == "report":
            return cmd_report(args)
        if args.command in REVIEW_COMMANDS:
            return cmd_review(args)
        return cmd_noargs()
    except ScError as exc:
        if getattr(args, "json", False):
            _print({"error": exc.message, "hint": exc.hint, "exit_code": errors.EXIT_ERROR}, True)
        sys.stderr.write(f"error: {exc}\n")
        return errors.EXIT_ERROR
    except KeyboardInterrupt:
        sys.stderr.write("interrumpido\n")
        return errors.EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
