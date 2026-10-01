"""Comando init: detecta el stack y genera una configuración mínima sin pisar la existente."""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from . import config as cfgmod, inventory as inv, miniyaml, schema as sch
from .errors import ConfigError

CHOICES = {"criticality": ("unknown", "low", "medium", "high", "critical"),
           "sox_scope": ("unknown", "yes", "no"), "contains_pii": ("unknown", "yes", "no"),
           "contains_financial_data": ("unknown", "yes", "no")}
PROMPTS = {"criticality": "Criticidad del proyecto", "sox_scope": "¿Está en alcance SOX según la organización?",
           "contains_pii": "¿Contiene datos personales (PII)?", "contains_financial_data": "¿Contiene datos financieros?"}


def _ask(key: str) -> str:
    opts = "/".join(CHOICES[key])
    ans = input(f"{PROMPTS[key]} [{opts}] (Enter = unknown): ").strip().lower()
    return ans if ans in CHOICES[key] else "unknown"


TEMPLATE = """# Configuración de security-compliance (opcional; generada por 'init').
# Los valores 'unknown' son válidos: el skill no infiere aplicabilidad (p. ej. SOX).
schema_version: 1
project:
  name: {name}
  criticality: {criticality}
  sox_scope: {sox_scope}
  contains_pii: {contains_pii}
  contains_financial_data: {contains_financial_data}
frameworks:
  - security
  - iso27001
  - sox_itgc
  - owasp_asvs
review:
  language: es
  invocation: assisted
  mode: advisory
  asvs_target_level: 2
network:
  allow_external_scanners: false
tools:
  sast: auto
  secrets: auto
  dependencies: auto
gate:
  block_severities: [critical, high]
  required_controls: []
  unknown_required: block
paths:
  include: ['.']
  exclude: [node_modules, dist, build, .venv]
reports:
  directory: .security-compliance/reports
"""


def run_init(project: Path, answers: Optional[Dict[str, str]] = None, interactive: bool = False,
             update_gitignore: bool = False) -> Dict[str, Any]:
    target = project / cfgmod.CONFIG_NAME
    if target.exists():
        try:
            cfgmod.read_config_file(target)
            note = "es válido"
        except ConfigError as exc:
            note = "tiene errores: " + str(exc).splitlines()[0]
        return {"created": False, "path": str(target), "message": f"{cfgmod.CONFIG_NAME} ya existe ({note}); no se modificó.",
                "stacks": {}, "gitignore": None}

    cfg = copy.deepcopy(cfgmod.DEFAULTS)
    excludes = cfgmod.effective_excludes(cfg)
    inventory = inv.build_inventory(project, cfg, excludes)
    stacks = inv.detect_stacks(project, inventory["files"])

    vals = {k: "unknown" for k in CHOICES}
    for k, v in (answers or {}).items():
        if v is not None:
            if v not in CHOICES[k]:
                raise ConfigError(f"Valor inválido para {k}: {v!r} (use {', '.join(CHOICES[k])})")
            vals[k] = v
    if interactive and sys.stdin.isatty():
        for k in CHOICES:
            if not (answers or {}).get(k):
                vals[k] = _ask(k)
    name = project.name if all(c.isalnum() or c in "-_. " for c in project.name) else "auto"
    text = TEMPLATE.format(name=name if name == "auto" else miniyaml_quote(name), **vals)
    if stacks:
        text += "# Stacks detectados al generar este archivo: " + ", ".join(stacks) + "\n"
    # autovalidación: nunca escribir una configuración que el propio runner rechazaría
    data = miniyaml.loads(text)
    errs = sch.validate(data, cfgmod.load_schema())
    if errs:
        raise ConfigError("Defecto interno: la configuración generada es inválida: " + "; ".join(errs[:3]))
    target.write_text(text, encoding="utf-8")

    gi_msg = None
    gi = project / ".gitignore"
    rep_dir = ".security-compliance/"
    gi_text = gi.read_text(encoding="utf-8", errors="ignore") if gi.is_file() else ""
    if rep_dir.strip("/") not in gi_text:
        if update_gitignore:
            with open(gi, "a", encoding="utf-8") as fh:
                fh.write(("\n" if gi_text and not gi_text.endswith("\n") else "") + "# security-compliance: reportes locales\n" + rep_dir + "\n")
            gi_msg = f"Se agregó '{rep_dir}' a .gitignore (solicitado con --update-gitignore)."
        else:
            gi_msg = (f"Los reportes (.security-compliance/reports) pueden contener datos sensibles: agregue '{rep_dir}' a "
                      ".gitignore (o repita init con --update-gitignore en un proyecto nuevo).")
    return {"created": True, "path": str(target), "message": f"Se creó {cfgmod.CONFIG_NAME}.", "stacks": stacks,
            "gitignore": gi_msg}


def miniyaml_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"
