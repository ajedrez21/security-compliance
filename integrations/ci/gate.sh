#!/bin/sh
# Gate de CI basado en el CLI de security-compliance (modo enforce).
#
# Uso:  gate.sh <skill-dir> <proyecto> <politica-confiable.yml> <salida> [<base-ref>] [<evidencia.json>]
#
# - La política DEBE venir de una ubicación confiable externa al cambio evaluado (p. ej. la rama base
#   u otro repositorio). El CLI rechaza en enforce una política ubicada dentro del proyecto.
# - Los reportes saneados quedan en <salida>/<run-id>/ aunque el gate falle; el código de salida del
#   CLI se propaga: 0 ok · 1 bloqueo · 2 error de configuración/runtime · 3 incompleto.
set -u
SKILL="$1"; PROJECT="$2"; POLICY="$3"; OUT="$4"; BASE="${5:-}"; EVIDENCE="${6:-}"
PY=python3; command -v "$PY" >/dev/null 2>&1 || PY=python
set -- pr --project "$PROJECT" --mode enforce --policy "$POLICY" --output "$OUT"
[ -n "$BASE" ] && set -- "$@" --base "$BASE"
[ -n "$EVIDENCE" ] && set -- "$@" --evidence "$EVIDENCE"
"$PY" "$SKILL/scripts/sc.py" "$@"
code=$?
latest=$(ls -1d "$OUT"/*/ 2>/dev/null | tail -n 1)
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -n "$latest" ] && [ -f "${latest}report.md" ]; then
  cat "${latest}report.md" >> "$GITHUB_STEP_SUMMARY"   # el Markdown ya está saneado (sin HTML ni secretos)
fi
exit $code
