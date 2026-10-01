#!/usr/bin/env sh
# Instala security-compliance (sin sudo). Ejemplos:
#   ./install.sh --client cursor --scope global
#   ./install.sh --client claude --scope project --project-path /repos/mi-app
#   ./install.sh --client codex --scope global --update
#   ./install.sh --client cursor --scope global --uninstall
# Opciones: --client cursor|claude|codex (repetible) --scope global|project --project-path DIR
#           --invocation assisted|manual --update --uninstall --dry-run --force --non-interactive
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    PY="$cand"; break
  fi
done
if [ -z "$PY" ]; then
  echo "error: se requiere Python >= 3.9 (python3 o python en PATH). El instalador no instala Python." >&2
  exit 2
fi
exec "$PY" "$DIR/installer/sc_install.py" "$@"
