# Quickstart

## 1. Instalar

Requisitos: Python 3.9+ (solo para el runner), git. Opcionales: Semgrep, Gitleaks, OSV-Scanner (el skill no los instala).

| Cliente | Windows (PowerShell) | macOS / Linux |
|---|---|---|
| Cursor | `.\install.ps1 -Client cursor -Scope global` | `./install.sh --client cursor --scope global` |
| Claude Code | `.\install.ps1 -Client claude -Scope global` | `./install.sh --client claude --scope global` |
| Codex | `.\install.ps1 -Client codex -Scope global` | `./install.sh --client codex --scope global` |

Por proyecto: agregue `-Scope project -ProjectPath C:\repos\mi-app` (`--scope project --project-path /repos/mi-app`). Pruebe antes con `-DryRun` / `--dry-run`. Sin administrador ni `sudo`.
Si PowerShell bloquea el script: `powershell -ExecutionPolicy Bypass -File .\install.ps1 …` (no se cambia la política global).

El instalador imprime ubicación, versión, comprobación ejecutada y el primer comando.

## 2. Verificar

```bash
python3 <ruta-instalada>/scripts/sc.py doctor --project .      # Windows: py -3 <ruta>\scripts\sc.py doctor --project .
```

`doctor` distingue «archivos instalados correctamente» de «descubrimiento comprobado dentro del cliente» (esto último lo confirma usted: abra el cliente y escriba `/security-compliance help`; en Codex `$security-compliance help`).

## 3. Primera revisión

En el cliente, en un proyecto con cambios:

```text
/security-compliance diff
```

o en lenguaje natural: «Usá el skill security-compliance para revisar los cambios actuales. Priorizá autorización, secretos y cambios de base de datos. Generá un reporte con evidencia y controles que no pudiste verificar.»

Sin cliente (solo el runner):

```bash
python3 <ruta-instalada>/scripts/sc.py diff --project . --output ./audit-output
python3 <ruta-instalada>/scripts/sc.py report --run ./audit-output/<run-id>
```

Resultado: `report.md` (qué se revisó, qué se encontró, qué bloquea, qué falta comprobar y cómo resolverlo) y `report.json`.
**Sin configuración** funciona; `sc.py init` crea `.security-compliance.yml` mínimo (opcional). Agregue `.security-compliance/` al `.gitignore`: los reportes pueden contener rutas y hallazgos sensibles.

Qué esperar: el runner no razona sobre autorización ni arquitectura; esos controles quedan `NOT_RUN` hasta que el agente aporte su revisión estructurada (el skill lo guía) y se reimporte con `--review`.

## 4. Corregir y volver a medir

Corregí los problemas de `remediation.md` y repetí el mismo comando: el reporte se actualiza con el progreso (resueltos, nuevos, sin reverificar) y la evolución. Detalle en `docs/COMMANDS.md`.
