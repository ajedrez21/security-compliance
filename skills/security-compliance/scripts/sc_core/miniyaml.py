"""Parser YAML seguro de subconjunto restringido (sin dependencias).

Soporta: mapeos anidados, listas de bloque, listas/mapas de flujo simples, escalares
(str, int, float, bool, null) y comentarios. Rechaza explícitamente lo que hace inseguro o
ambiguo a YAML: anclas/alias, tags, escalares de bloque, documentos múltiples, tabulaciones
de sangría y claves duplicadas. No construye objetos arbitrarios.
"""
from __future__ import annotations

import re
from typing import Any, List, Tuple


class YamlError(ValueError):
    pass


_INT = re.compile(r"^[-+]?\d+$")
_FLOAT = re.compile(r"^[-+]?\d+\.\d+$")


def _strip_comment(raw: str) -> str:
    quote = ""
    for i, ch in enumerate(raw):
        if quote:
            if ch == "\\" and quote == '"':
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            # una comilla solo abre un escalar al inicio de un valor
            prev = raw[:i].rstrip()
            if not prev or prev[-1] in ":-[{,":
                quote = ch
        elif ch == "#" and (i == 0 or raw[i - 1] in " \t"):
            return raw[:i].rstrip()
    return raw.rstrip()


def _split_key(content: str, lineno: int):
    """Devuelve (clave, resto) si la línea es 'clave: valor'; None si no es un mapeo."""
    if content and content[0] in "\"'":
        q = content[0]
        end = content.find(q, 1)
        if end == -1:
            return None
        key = content[1:end]
        rest = content[end + 1:]
        if rest.startswith(":") and (len(rest) == 1 or rest[1] == " "):
            return key, rest[1:].strip()
        return None
    m = re.match(r"^([^\s:\[\]{},#&*!|>'\"%@`][^:]*?)\s*:(?:\s+(.*))?$", content)
    if not m:
        return None
    return m.group(1).strip(), (m.group(2) or "").strip()


def _scalar(token: str, lineno: int) -> Any:
    if token == "":
        return None
    c = token[0]
    if c in "&*!|>%@`":
        raise YamlError(
            f"línea {lineno}: construcción YAML no permitida ({c!r}): anclas, alias, tags y "
            "escalares de bloque no están soportados")
    if c == '"':
        if len(token) < 2 or not token.endswith('"'):
            raise YamlError(f"línea {lineno}: comillas sin cerrar")
        body = token[1:-1]
        out, i = [], 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\", "/": "/"}.get(nxt, "\\" + nxt))
                i += 2
            else:
                out.append(body[i])
                i += 1
        return "".join(out)
    if c == "'":
        if len(token) < 2 or not token.endswith("'"):
            raise YamlError(f"línea {lineno}: comillas sin cerrar")
        return token[1:-1].replace("''", "'")
    if c in "[{":
        return _flow(token, lineno)
    low = token.lower()
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    if low in ("null", "~"):
        return None
    if _INT.match(token):
        return int(token)
    if _FLOAT.match(token):
        return float(token)
    return token


def _flow(text: str, lineno: int) -> Any:
    pos = 0

    def skip():
        nonlocal pos
        while pos < len(text) and text[pos] in " \t":
            pos += 1

    def parse_item(stop: str) -> Any:
        nonlocal pos
        skip()
        if pos >= len(text):
            raise YamlError(f"línea {lineno}: colección de flujo sin cerrar")
        ch = text[pos]
        if ch == "[":
            pos += 1
            items: List[Any] = []
            skip()
            if pos < len(text) and text[pos] == "]":
                pos += 1
                return items
            while True:
                items.append(parse_item(",]"))
                skip()
                if pos < len(text) and text[pos] == ",":
                    pos += 1
                    skip()
                    if pos < len(text) and text[pos] == "]":  # coma final
                        pos += 1
                        return items
                    continue
                if pos < len(text) and text[pos] == "]":
                    pos += 1
                    return items
                raise YamlError(f"línea {lineno}: lista de flujo inválida")
        if ch == "{":
            pos += 1
            obj: dict = {}
            skip()
            if pos < len(text) and text[pos] == "}":
                pos += 1
                return obj
            while True:
                skip()
                k = parse_item(":")
                skip()
                if pos >= len(text) or text[pos] != ":":
                    raise YamlError(f"línea {lineno}: mapa de flujo inválido")
                pos += 1
                v = parse_item(",}")
                if k in obj:
                    raise YamlError(f"línea {lineno}: clave duplicada {k!r}")
                obj[k] = v
                skip()
                if pos < len(text) and text[pos] == ",":
                    pos += 1
                    continue
                if pos < len(text) and text[pos] == "}":
                    pos += 1
                    return obj
                raise YamlError(f"línea {lineno}: mapa de flujo inválido")
        if ch in "\"'":
            end = pos + 1
            while end < len(text):
                if text[end] == "\\" and ch == '"':
                    end += 2
                    continue
                if text[end] == ch:
                    if ch == "'" and end + 1 < len(text) and text[end + 1] == "'":
                        end += 2
                        continue
                    break
                end += 1
            token = text[pos:end + 1]
            pos = end + 1
            return _scalar(token, lineno)
        start = pos
        while pos < len(text) and text[pos] not in stop:
            pos += 1
        return _scalar(text[start:pos].strip(), lineno)

    value = parse_item("")
    skip()
    if pos != len(text):
        raise YamlError(f"línea {lineno}: texto inesperado tras la colección de flujo")
    return value


Line = Tuple[int, str, int]  # (sangría, contenido, nº de línea)


def loads(text: str) -> Any:
    lines: List[Line] = []
    seen_doc = False
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.startswith("\ufeff"):
            raw = raw[1:]
        indent_ws = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in indent_ws:
            raise YamlError(f"línea {n}: tabulaciones en la sangría no permitidas")
        s = _strip_comment(raw)
        if not s.strip():
            continue
        if s.strip() == "---":
            if seen_doc or lines:
                raise YamlError(f"línea {n}: documentos YAML múltiples no soportados")
            seen_doc = True
            continue
        if s.strip() == "...":
            raise YamlError(f"línea {n}: marcador de fin de documento no soportado")
        lines.append((len(s) - len(s.lstrip(" ")), s.strip(), n))
    if not lines:
        return None
    value, idx = _block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise YamlError(f"línea {lines[idx][2]}: sangría inesperada")
    return value


def _is_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _block(lines: List[Line], idx: int, indent: int):
    if _is_item(lines[idx][1]):
        return _list(lines, idx, indent)
    return _map(lines, idx, indent)


def _list(lines: List[Line], idx: int, indent: int):
    out: List[Any] = []
    while idx < len(lines):
        ind, content, n = lines[idx]
        if ind < indent:
            break
        if ind > indent:
            raise YamlError(f"línea {n}: sangría inesperada en lista")
        if not _is_item(content):
            break
        rest = content[1:].lstrip()
        if not rest:
            if idx + 1 < len(lines) and lines[idx + 1][0] > indent:
                val, idx = _block(lines, idx + 1, lines[idx + 1][0])
            else:
                val, idx = None, idx + 1
            out.append(val)
            continue
        col = ind + (len(content) - len(rest))
        if _is_item(rest) or _split_key(rest, n) is not None:
            lines[idx] = (col, rest, n)
            val, idx = _block(lines, idx, col)
        else:
            val, idx = _scalar(rest, n), idx + 1
        out.append(val)
    return out, idx


def _map(lines: List[Line], idx: int, indent: int):
    out: dict = {}
    while idx < len(lines):
        ind, content, n = lines[idx]
        if ind < indent:
            break
        if ind > indent:
            raise YamlError(f"línea {n}: sangría inesperada")
        if _is_item(content):
            break
        kv = _split_key(content, n)
        if kv is None:
            raise YamlError(f"línea {n}: se esperaba 'clave: valor'")
        key, rest = kv
        if key in out:
            raise YamlError(f"línea {n}: clave duplicada {key!r}")
        if rest == "":
            nxt = lines[idx + 1] if idx + 1 < len(lines) else None
            if nxt and (nxt[0] > indent or (nxt[0] == indent and _is_item(nxt[1]))):
                out[key], idx = _block(lines, idx + 1, nxt[0])
            else:
                out[key], idx = None, idx + 1
        else:
            out[key] = _scalar(rest, n)
            idx += 1
    return out, idx
