"""Carga, validación, precedencia y hash de la configuración efectiva."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Optional, Tuple

from . import SKILL_ROOT, miniyaml, schema as sch
from .errors import ConfigError

CONFIG_NAME = ".security-compliance.yml"
FORBIDDEN_KEYS = {"command", "commands", "cmd", "script", "scripts", "run", "exec", "shell",
                  "hooks", "hook", "args", "binary", "executable", "env"}

DEFAULTS: Dict[str, Any] = {
    "schema_version": 1,
    "project": {"name": "auto", "repo": "", "criticality": "unknown", "sox_scope": "unknown",
                "contains_pii": "unknown", "contains_financial_data": "unknown"},
    "frameworks": ["security", "iso27001", "sox_itgc", "owasp_asvs"],
    "review": {"language": "es", "invocation": "assisted", "mode": "advisory",
               "asvs_target_level": 2},
    "network": {"allow_external_scanners": False},
    "tools": {"sast": "auto", "secrets": "auto", "dependencies": "auto", "timeout_seconds": 300},
    "itgc": {"min_approvals": 1, "emergency_change_policy": "unknown"},
    "gate": {"block_severities": ["critical", "high"], "required_controls": [],
             "unknown_required": "block"},
    "paths": {"include": ["."], "exclude": ["node_modules", "dist", "build", ".venv"]},
    "reports": {"directory": ".security-compliance/reports"},
    "exceptions": [],
    "trust": {"agent_review": True, "user_supplied_evidence": True},
}

# Exclusiones implícitas que no se pueden quitar (metadatos y reportes propios).
IMPLICIT_EXCLUDES = [".git", ".security-compliance"]


def _check_forbidden(node: Any, where: str = "") -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                raise ConfigError(
                    f"{where}{k}: campo no permitido. La configuración no acepta comandos, scripts "
                    "ni variables de entorno ejecutables definidos por el repositorio.")
            _check_forbidden(v, f"{where}{k}.")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _check_forbidden(v, f"{where}[{i}].")


def load_schema() -> Dict[str, Any]:
    return sch.load_schema(SKILL_ROOT / "schemas" / "config.schema.json")


def read_config_file(path: Path) -> Dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"No se pudo leer {path}: {exc}") from exc
    if len(raw) > 200_000:
        raise ConfigError(f"{path.name} excede el tamaño máximo (200 KB)")
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(raw)
        else:
            data = miniyaml.loads(raw)
    except (miniyaml.YamlError, ValueError) as exc:
        raise ConfigError(f"{path.name}: YAML/JSON inválido o no permitido: {exc}",
                          "Use solo el subconjunto documentado (ver assets/config.example.yml).") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name}: debe ser un mapeo en la raíz")
    _check_forbidden(data)
    errors = sch.validate(data, load_schema())
    if errors:
        raise ConfigError(f"{path.name}: configuración inválida:\n  - " + "\n  - ".join(errors[:15]))
    return data


def _check_paths(cfg: Dict[str, Any], project_root: Path) -> None:
    for key in ("include", "exclude"):
        for p in cfg["paths"][key]:
            _check_rel(p, f"paths.{key}")
    _check_rel(cfg["reports"]["directory"], "reports.directory")


def _check_rel(p: str, where: str) -> None:
    if os.path.isabs(p) or PurePosixPath(p.replace("\\", "/")).is_absolute() or ":" in p[:3]:
        raise ConfigError(f"{where}: la ruta {p!r} debe ser relativa al proyecto")
    parts = PurePosixPath(p.replace("\\", "/")).parts
    if ".." in parts:
        raise ConfigError(f"{where}: la ruta {p!r} escapa del alcance del proyecto")


def deep_merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_effective(project_root: Path, config_path: Optional[Path] = None,
                   flags: Optional[Dict[str, Any]] = None,
                   policy_path: Optional[Path] = None,
                   enforce: bool = False,
                   allow_project_policy: bool = False) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """defaults → configuración del proyecto → flags; política confiable prevalece en gate/paths/trust.

    Devuelve (config_efectiva, meta) con meta = {config_file, config_found, policy_source,
    policy_file, config_hash, notes}.
    """
    meta: Dict[str, Any] = {"config_file": None, "config_found": False, "policy_source": "defaults",
                            "policy_file": None, "notes": []}
    cfg = copy.deepcopy(DEFAULTS)

    cfg_file = config_path or (project_root / CONFIG_NAME)
    project_cfg: Dict[str, Any] = {}
    if cfg_file.is_file():
        project_cfg = read_config_file(cfg_file)
        cfg = deep_merge(cfg, project_cfg)
        meta["config_file"] = CONFIG_NAME if cfg_file.parent == project_root else str(cfg_file)
        meta["config_found"] = True
        meta["policy_source"] = "project_config"
        # 'trust' del YAML del proyecto no se respeta: el PR no puede otorgarse confianza.
        if "trust" in project_cfg:
            cfg["trust"] = copy.deepcopy(DEFAULTS["trust"])
            meta["notes"].append("'trust' en la configuración del proyecto se ignora; solo una "
                                 "política confiable (--policy) puede definirlo.")
    elif config_path is not None:
        raise ConfigError(f"No existe el archivo de configuración {config_path}")

    for key, val in (flags or {}).items():
        if val is None:
            continue
        section, _, name = key.partition(".")
        cfg.setdefault(section, {})[name] = val

    if policy_path is not None:
        pol = read_config_file(policy_path)
        inside = _is_inside(policy_path, project_root)
        if inside and enforce and not allow_project_policy:
            raise ConfigError(
                f"La política {policy_path} está dentro del proyecto auditado; en modo enforce "
                "debe provenir de una ubicación confiable externa al cambio evaluado.",
                "Obténgala de la rama base o de otro repositorio (ver integrations/ci).")
        # Bajo política confiable, estas secciones salen SOLO de la política (o de los defaults): el YAML del
        # cambio evaluado no puede rebajar umbrales, excluir rutas, declarar "fuera de alcance SOX" ni
        # alterar a qué repositorio pertenece la evidencia.
        for section in ("gate", "itgc", "paths"):
            cfg[section] = deep_merge(DEFAULTS[section], pol.get(section, {}))
        cfg["trust"] = deep_merge({"agent_review": False, "user_supplied_evidence": False}, pol.get("trust", {}))
        for k in ("sox_scope", "criticality", "contains_pii", "contains_financial_data", "repo"):
            cfg["project"][k] = (pol.get("project") or {}).get(k, DEFAULTS["project"][k])
        cfg["frameworks"] = pol.get("frameworks", DEFAULTS["frameworks"])
        cfg["exceptions"] = pol.get("exceptions", [])   # excepciones del proyecto no se aceptan bajo política confiable
        cfg["_exceptions_trusted"] = True
        meta["policy_source"] = "trusted_policy"
        meta["policy_file"] = str(policy_path.name)
        if project_cfg and any(project_cfg.get(s) not in (None, {}) and project_cfg.get(s) != pol.get(s)
                               for s in ("gate", "paths")):
            meta["notes"].append("La política confiable sustituyó valores de gate/paths definidos en "
                                 "el YAML del proyecto.")
    else:
        cfg["_exceptions_trusted"] = False

    _check_paths(cfg, project_root)
    from .catalog import load_catalog  # import tardío para evitar ciclos
    known = {c["id"] for c in load_catalog()["controls"]}
    for cid in cfg["gate"]["required_controls"]:
        if cid not in known:
            raise ConfigError(f"gate.required_controls: control desconocido {cid!r}")
    if enforce and meta["policy_source"] != "trusted_policy" and not allow_project_policy:
        raise ConfigError(
            "El modo enforce requiere una política confiable externa (--policy).",
            "Use --policy <archivo> (ver integrations/ci) o --allow-project-policy solo para "
            "ejecución local, donde el YAML del proyecto no es una política confiable.")
    meta["config_hash"] = config_hash(cfg)
    return cfg, meta


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def config_hash(cfg: Dict[str, Any]) -> str:
    canon = json.dumps({k: v for k, v in cfg.items() if not k.startswith("_")},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def effective_excludes(cfg: Dict[str, Any]) -> list:
    out = list(IMPLICIT_EXCLUDES)
    for p in cfg["paths"]["exclude"]:
        if p not in out:
            out.append(p)
    return out
