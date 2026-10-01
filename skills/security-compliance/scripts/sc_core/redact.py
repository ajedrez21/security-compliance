"""Saneamiento de texto antes de persistir o imprimir (secretos, credenciales, control chars)."""
from __future__ import annotations

import os
import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS = [
    # URLs con credenciales: scheme://user:pass@host
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s/@:]+:[^\s/@]+@"), r"\1" + REDACTED + "@"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
     REDACTED + " (private key)"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), REDACTED),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), REDACTED),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{16,}"), r"\1 " + REDACTED),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"
                r"(\s*[:=]\s*)(['\"]?)[^\s'\",;]{6,}\3"),
     r"\1\2" + REDACTED),
]

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(text: str, limit: int = 2000) -> str:
    """Quita caracteres de control, redacta credenciales conocidas y trunca."""
    if not isinstance(text, str):
        text = str(text)
    text = _CTRL.sub("", text)
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    if len(text) > limit:
        text = text[:limit] + "…[truncado]"
    return text


def sanitize_obj(obj: Any, limit: int = 2000) -> Any:
    """Aplica sanitize_text a todas las cadenas de una estructura JSON."""
    if isinstance(obj, str):
        return sanitize_text(obj, limit)
    if isinstance(obj, list):
        return [sanitize_obj(x, limit) for x in obj]
    if isinstance(obj, dict):
        return {k: sanitize_obj(v, limit) for k, v in obj.items()}
    return obj


def display_path(path: str) -> str:
    """Ruta saneada para reportes: reemplaza el home del usuario por '~'."""
    home = os.path.expanduser("~")
    p = str(path)
    if home and home != "~" and p.startswith(home):
        p = "~" + p[len(home):]
    return sanitize_text(p, 500)


def sanitize_command(argv: list) -> str:
    """Comando saneado para el reporte (sin credenciales ni rutas temporales ruidosas)."""
    return sanitize_text(" ".join(str(a) for a in argv), 800)


_STRONG = _PATTERNS[:8]   # URL con credenciales, clave privada, AKIA, gh*, glpat, xox*, sk-, JWT


def final_scrub(text: str) -> str:
    """Última barrera antes de persistir: redacta solo patrones de alta confianza (sin truncar)."""
    for pat, repl in _STRONG:
        text = pat.sub(repl, text)
    return text
