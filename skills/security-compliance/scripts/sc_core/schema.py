"""Validador JSON Schema (subconjunto) sin dependencias.

Cubre las palabras clave usadas por los schemas de este skill: type, enum, const, properties,
required, additionalProperties, items, minItems, maxItems, uniqueItems, minLength, maxLength,
pattern, minimum, maximum, format (date-time/date), oneOf, anyOf, allOf, $ref local
(#/$defs/... o #/definitions/...). Las palabras clave no soportadas se rechazan al cargar el
schema (en vez de ignorarlas en silencio).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

SUPPORTED = {
    "$schema", "$id", "$ref", "$defs", "definitions", "title", "description", "type", "enum",
    "const", "properties", "required", "additionalProperties", "items", "minItems", "maxItems",
    "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "format", "oneOf",
    "anyOf", "allOf", "default", "examples",
}

_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:?\d{2})$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class SchemaDefinitionError(ValueError):
    pass


def load_schema(path: Path) -> Dict[str, Any]:
    schema = json.loads(Path(path).read_text(encoding="utf-8"))
    check_schema(schema)
    return schema


def check_schema(node: Any, where: str = "#") -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k not in SUPPORTED:
                raise SchemaDefinitionError(f"{where}: palabra clave no soportada {k!r}")
            if k in ("properties", "$defs", "definitions"):
                for name, sub in v.items():
                    check_schema(sub, f"{where}/{k}/{name}")
            elif k in ("items", "additionalProperties") and isinstance(v, dict):
                check_schema(v, f"{where}/{k}")
            elif k in ("oneOf", "anyOf", "allOf"):
                for i, sub in enumerate(v):
                    check_schema(sub, f"{where}/{k}/{i}")


def _type_ok(value: Any, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "null":
        return value is None
    raise SchemaDefinitionError(f"tipo desconocido {t!r}")


def _resolve(root: Dict[str, Any], ref: str) -> Dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaDefinitionError(f"$ref no local no soportado: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def validate(instance: Any, schema: Dict[str, Any], root: Dict[str, Any] = None,
             path: str = "$") -> List[str]:
    """Devuelve la lista de errores (vacía si es válido)."""
    root = root or schema
    errors: List[str] = []
    if "$ref" in schema:
        return validate(instance, _resolve(root, schema["$ref"]), root, path)

    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_type_ok(instance, x) for x in types):
            return [f"{path}: se esperaba {'|'.join(types)}, se obtuvo {_name(instance)}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: debe ser {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: valor {instance!r} fuera de {schema['enum']}")

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: longitud menor a {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longitud mayor a {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: no cumple el patrón {schema['pattern']}")
        fmt = schema.get("format")
        if fmt == "date-time" and not _DATETIME.match(instance):
            errors.append(f"{path}: no es un date-time ISO 8601")
        if fmt == "date" and not _DATE.match(instance):
            errors.append(f"{path}: no es una fecha YYYY-MM-DD")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: menor que {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: mayor que {schema['maximum']}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: menos de {schema['minItems']} elementos")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: más de {schema['maxItems']} elementos")
        if schema.get("uniqueItems"):
            seen = [json.dumps(x, sort_keys=True) for x in instance]
            if len(seen) != len(set(seen)):
                errors.append(f"{path}: elementos duplicados")
        if "items" in schema:
            for i, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], root, f"{path}[{i}]"))

    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: falta la propiedad requerida {req!r}")
        for k, v in instance.items():
            if k in props:
                errors.extend(validate(v, props[k], root, f"{path}.{k}"))
            else:
                ap = schema.get("additionalProperties", True)
                if ap is False:
                    errors.append(f"{path}: propiedad desconocida {k!r}")
                elif isinstance(ap, dict):
                    errors.extend(validate(v, ap, root, f"{path}.{k}"))

    for kw in ("allOf",):
        for sub in schema.get(kw, []):
            errors.extend(validate(instance, sub, root, path))
    if "anyOf" in schema:
        if not any(not validate(instance, s, root, path) for s in schema["anyOf"]):
            errors.append(f"{path}: no cumple ninguna alternativa (anyOf)")
    if "oneOf" in schema:
        ok = sum(1 for s in schema["oneOf"] if not validate(instance, s, root, path))
        if ok != 1:
            errors.append(f"{path}: debe cumplir exactamente una alternativa (cumple {ok})")
    return errors


def _name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    return type(value).__name__
