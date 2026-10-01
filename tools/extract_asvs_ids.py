#!/usr/bin/env python3
"""Genera controls/baselines.json a partir del JSON oficial de ASVS 5.0.0 (solo IDs y niveles).

Uso: python tools/extract_asvs_ids.py <OWASP_ASVS_5.0.0_en.json>
Fuente: https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/docs_en (se guardan IDs y niveles, no el
texto de los requisitos).
"""
import json
import sys
from pathlib import Path

src = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
chapters, reqs = {}, {}
for ch in src["Requirements"]:
    chapters[ch["Shortcode"]] = ch["Name"]
    for sec in ch["Items"]:
        for it in sec["Items"]:
            reqs[it["Shortcode"]] = int(it["L"])
baselines = {
    "schema_version": 1,
    "baselines": {
        "owasp_asvs": {
            "name": "OWASP Application Security Verification Standard",
            "version": "5.0.0",
            "source": "https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release",
            "retrieved": "2026-09-30",
            "status": "baseline propuesta; no se actualiza en silencio",
            "chapters": chapters,
            "requirement_levels": reqs,
            "requirement_count": len(reqs),
        },
        "iso27001": {
            "name": "ISO/IEC 27001",
            "version": "2022",
            "source": "https://www.iso.org/standard/27001",
            "retrieved": "2026-09-30",
            "status": "referencia propuesta; la norma es de pago y no se pudo consultar su texto: "
                      "los mappings son temáticos y NO validados",
        },
        "sox_itgc": {
            "name": "Controles ITGC de apoyo (ruleset propio)",
            "version": "1.0",
            "source": "Ruleset propio; no es un mandato literal de SOX/SEC/PCAOB",
            "retrieved": "2026-09-30",
            "status": "depende del alcance y de las políticas de la organización",
        },
    },
}
out = Path(__file__).resolve().parent.parent / "skills/security-compliance/controls/baselines.json"
out.write_text(json.dumps(baselines, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print("requisitos:", len(reqs), "→", out)
