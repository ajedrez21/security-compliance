"""Validación del paquete del skill: frontmatter (Agent Skills), referencias internas e integridad."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from . import miniyaml

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ALLOWED_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools",
                  "disable-model-invocation"}
LINK_RE = re.compile(r"(?:\]\(|`)((?:references|scripts|assets|rules|schemas|controls)/[A-Za-z0-9_./\-]+)(?:\)|`|\s|$)")
REQUIRED_FILES = ["SKILL.md", "VERSION", "controls/catalog.json", "controls/baselines.json", "scripts/sc.py",
                  "schemas/config.schema.json", "schemas/report.schema.json", "schemas/finding.schema.json",
                  "schemas/evidence.schema.json", "schemas/review.schema.json", "rulesets/semgrep-local.yml"]
MARKER = ".sc-install.json"


def split_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    if not text.startswith("---"):
        raise ValueError("SKILL.md debe comenzar con '---' (frontmatter YAML)")
    parts = text.split("\n---", 1)
    if len(parts) != 2:
        raise ValueError("frontmatter sin cierre '---'")
    fm = miniyaml.loads(parts[0][3:].lstrip("\n"))
    if not isinstance(fm, dict):
        raise ValueError("frontmatter inválido")
    return fm, parts[1].lstrip("-").lstrip("\n")


def validate_frontmatter(fm: Dict[str, Any], dirname: str) -> List[str]:
    errs: List[str] = []
    name, desc = fm.get("name"), fm.get("description")
    if not isinstance(name, str) or not name:
        errs.append("falta 'name'")
    else:
        if len(name) > 64 or not NAME_RE.match(name):
            errs.append("'name' debe tener 1-64 caracteres: minúsculas, números y guiones simples, sin guion al inicio/fin")
        if name != dirname:
            errs.append(f"'name' ({name}) debe coincidir con el directorio ({dirname})")
    if not isinstance(desc, str) or not desc.strip():
        errs.append("falta 'description'")
    elif len(desc) > 1024:
        errs.append(f"'description' excede 1024 caracteres ({len(desc)})")
    if "compatibility" in fm and (not isinstance(fm["compatibility"], str) or not 1 <= len(fm["compatibility"]) <= 500):
        errs.append("'compatibility' debe ser texto de 1-500 caracteres")
    if "metadata" in fm and (not isinstance(fm["metadata"], dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in fm["metadata"].items())):
        errs.append("'metadata' debe ser un mapa string→string")
    for k in fm:
        if k not in ALLOWED_FIELDS:
            errs.append(f"campo de frontmatter no soportado por la especificación: {k}")
    return errs


def validate_package(skill_root: Path) -> Dict[str, Any]:
    """Valida un directorio de skill (checkout o instalado). Devuelve {ok, errors, warnings, references}."""
    errors: List[str] = []
    warnings: List[str] = []
    skill_md = skill_root / "SKILL.md"
    refs: List[str] = []
    for rel in REQUIRED_FILES:
        if not (skill_root / rel).is_file():
            errors.append(f"falta el archivo requerido: {rel}")
    if skill_md.is_file():
        text = skill_md.read_text(encoding="utf-8")
        try:
            fm, body = split_frontmatter(text)
            errors += validate_frontmatter(fm, skill_root.name)
            if len(text.splitlines()) > 500:
                warnings.append("SKILL.md excede 500 líneas (recomendación de la especificación)")
        except (ValueError, miniyaml.YamlError) as exc:
            errors.append(f"frontmatter: {exc}")
            body = text
        refs = sorted(set(LINK_RE.findall(body)))
        for r in refs:
            if not (skill_root / r.rstrip("/")).exists():
                errors.append(f"referencia interna rota en SKILL.md: {r}")
    # referencias entre documentos de references/
    for md in sorted((skill_root / "references").rglob("*.md")) if (skill_root / "references").is_dir() else []:
        for r in sorted(set(LINK_RE.findall(md.read_text(encoding="utf-8")))):
            if not (skill_root / r.rstrip("/")).exists():
                errors.append(f"referencia interna rota en {md.relative_to(skill_root)}: {r}")
    return {"ok": not errors, "errors": errors, "warnings": warnings, "references": refs}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_marker(skill_root: Path) -> Dict[str, Any]:
    """Compara los archivos instalados con el manifiesto de la instalación (si existe)."""
    mp = skill_root / MARKER
    if not mp.is_file():
        return {"installed": False, "reason": "sin marcador .sc-install.json (checkout de desarrollo o copia manual)"}
    try:
        marker = json.loads(mp.read_text(encoding="utf-8"))
    except ValueError:
        return {"installed": True, "intact": False, "reason": "marcador ilegible"}
    modified, missing = [], []
    for rel, digest in marker.get("files", {}).items():
        p = skill_root / rel
        if not p.is_file():
            missing.append(rel)
        elif sha256_file(p) != digest:
            modified.append(rel)
    return {"installed": True, "intact": not (modified or missing), "version": marker.get("version"),
            "client": marker.get("client"), "scope": marker.get("scope"), "invocation": marker.get("invocation"),
            "modified": modified, "missing": missing}
