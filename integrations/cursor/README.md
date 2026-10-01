# Cursor

Rutas y sintaxis verificadas contra https://cursor.com/docs/skills el 2026-09-30 (ver `docs/COMPATIBILITY.md`).

## Instalar

| Alcance | Windows (PowerShell) | macOS / Linux |
|---|---|---|
| Global | `.\install.ps1 -Client cursor -Scope global` → `%USERPROFILE%\.cursor\skills\security-compliance` | `./install.sh --client cursor --scope global` → `~/.cursor/skills/security-compliance` |
| Proyecto | `.\install.ps1 -Client cursor -Scope project -ProjectPath C:\repos\mi-app` → `<proyecto>\.cursor\skills\security-compliance` | `./install.sh --client cursor --scope project --project-path /repos/mi-app` |

Sin administrador ni `sudo`. Requiere Python 3.9+ (`py -3`, `python` o `python3`) solo para el runner. Si PowerShell bloquea el script: `powershell -ExecutionPolicy Bypass -File .\install.ps1 -Client cursor -Scope global` (el instalador no cambia la política global).
Primero pruebe con `-DryRun` / `--dry-run`.

## Verificar el descubrimiento (el instalador solo comprueba archivos)

1. Reinicie o recargue Cursor y abra el chat del **Agent**.
2. Escriba `/` y busque `security-compliance` (Cursor lista los skills en el menú `/`).
3. Ejecute `/security-compliance help`. Debe mostrar la ayuda corta.
   Si no aparece: `python <ruta-instalada>/scripts/sc.py doctor`, revise duplicados (Cursor también lee `.agents/skills`, `.claude/skills` y `.codex/skills`) y consulte `docs/COMPATIBILITY.md`.

## Uso

- Manual: `/security-compliance help` · `/security-compliance diff` · `/security-compliance audit` · `/security-compliance sox`.
- Lenguaje natural: «Usá el skill security-compliance para revisar los cambios actuales. Priorizá autorización, secretos y cambios de base de datos. Generá un reporte con evidencia y controles que no pudiste verificar.»
- Asistido: por defecto Cursor puede elegir el skill según su `description` (no garantizado).
- **Solo manual:** instale con `--invocation manual` (`-Invocation manual`): agrega `disable-model-invocation: true`, y el skill solo aparece al invocarlo con `/`. Esto controla el descubrimiento por el agente, no obliga a nadie a ejecutarlo: la obligatoriedad real requiere CI (ver `integrations/ci`).

## Actualizar / desinstalar

```powershell
.\install.ps1 -Client cursor -Scope global -Update        # respaldo + rollback; avisa si hay cambios locales
.\install.ps1 -Client cursor -Scope global -Uninstall     # solo archivos propios; preserva modificados y ajenos
```

```bash
./install.sh --client cursor --scope global --update
./install.sh --client cursor --scope global --uninstall
```

Los respaldos quedan en `~/.security-compliance/backups` (o `<proyecto>/.security-compliance/backups`).

## Límites

- Hooks de Cursor: **no implementados** (extensión opcional pendiente; ver `docs/IMPLEMENTATION-STATUS.md`).
- No se instalan reglas «always apply» ni se modifican `AGENTS.md` ni la configuración global de Cursor.
- Validación dentro de Cursor 3.16.17: **pendiente** (la instalación en rutas temporales se probó sin abrir Cursor).
