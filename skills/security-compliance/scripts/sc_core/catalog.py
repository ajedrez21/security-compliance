"""Carga del catálogo/baselines y selección de controles por comando."""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Dict, List, Set

from . import SKILL_ROOT


@lru_cache(maxsize=1)
def load_catalog() -> Dict[str, Any]:
    return json.loads((SKILL_ROOT / "controls" / "catalog.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_baselines() -> Dict[str, Any]:
    return json.loads((SKILL_ROOT / "controls" / "baselines.json").read_text(encoding="utf-8"))["baselines"]


def by_id() -> Dict[str, Dict[str, Any]]:
    return {c["id"]: c for c in load_catalog()["controls"]}


# comando → (filtro de dominio/framework)
def select_controls(command: str, frameworks: List[str]) -> List[Dict[str, Any]]:
    """Devuelve los controles seleccionados (con 'selection' = motivo) para un comando."""
    cat = load_catalog()["controls"]
    idx = by_id()
    chosen: Dict[str, str] = {}

    def pick(pred, reason):
        for c in cat:
            if pred(c) and c["id"] not in chosen:
                chosen[c["id"]] = reason

    if command == "audit":
        fw = set(frameworks)
        pick(lambda c: bool(fw & set(c["frameworks"])), "framework configurado")
    elif command == "diff":
        pick(lambda c: c["domain"] == "security", "revisión de cambios")
    elif command == "pr":
        pick(lambda c: c["domain"] == "security" or c["id"].startswith("ITGC-CHG-"), "revisión de PR")
    elif command == "sox":
        pick(lambda c: c["domain"] == "itgc", "controles ITGC")
    elif command == "iso":
        pick(lambda c: c["domain"] == "iso", "controles técnicos ISO")
    elif command == "security":
        pick(lambda c: c["domain"] == "security", "seguridad de aplicación")
    elif command == "secrets":
        pick(lambda c: c["id"] == "SEC-SECRETS-001", "comando secrets")
    elif command == "dependencies":
        pick(lambda c: c["id"] in ("SEC-DEPS-001", "SEC-DEPS-002"), "comando dependencies")
    else:
        raise ValueError(f"comando sin selección de controles: {command}")

    # cierre de derivaciones: los controles de soporte se evalúan pero se marcan como tales
    changed = True
    while changed:
        changed = False
        for cid in list(chosen):
            for d in idx[cid]["derived_from"]:
                if d not in chosen:
                    chosen[d] = f"soporte de {cid}"
                    changed = True
    out = []
    for c in cat:
        if c["id"] in chosen:
            item = dict(c)
            item["selection"] = chosen[c["id"]]
            out.append(item)
    return out


def asvs_coverage(selected: List[Dict[str, Any]], target_level: int) -> Dict[str, Any]:
    levels = load_baselines()["owasp_asvs"]["requirement_levels"]
    refs: Set[str] = set()
    for c in selected:
        for m in c["mappings"]:
            if m["framework"] == "owasp_asvs" and m["ref"] in levels:
                refs.add(m["ref"])
    in_target = {r for r in refs if levels[r] <= target_level}
    total_target = sum(1 for v in levels.values() if v <= target_level)
    return {
        "baseline": "OWASP ASVS " + load_baselines()["owasp_asvs"]["version"],
        "target_level": target_level,
        "requirements_referenced": len(refs),
        "requirements_referenced_within_target": len(in_target),
        "requirements_in_target_level": total_target,
        "statement": ("Cantidad de requisitos ASVS referenciados por los controles seleccionados. NO es "
                      "verificación ni conformidad de ningún nivel ASVS."),
    }
