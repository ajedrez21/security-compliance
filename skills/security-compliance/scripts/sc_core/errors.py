"""Códigos de salida estables y excepciones del runner."""
from __future__ import annotations

EXIT_OK = 0           # ejecución aceptable según el modo
EXIT_BLOCKED = 1      # bloqueo de política (solo en modo enforce)
EXIT_ERROR = 2        # error de configuración / runtime / argumentos
EXIT_INCOMPLETE = 3   # evaluación incompleta (solo en modo enforce)

# Precedencia cuando coinciden varias condiciones: 2 > 1 > 3 > 0.


class ScError(Exception):
    """Error controlado; se traduce a EXIT_ERROR con un mensaje accionable."""

    exit_code = EXIT_ERROR

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        return self.message + (f"\n  → {self.hint}" if self.hint else "")


class ConfigError(ScError):
    pass


class UsageError(ScError):
    pass


class GitError(ScError):
    pass


class EvidenceError(ScError):
    pass
