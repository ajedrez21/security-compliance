# Claude Code

Rutas y sintaxis verificadas contra https://code.claude.com/docs/en/skills el 2026-09-30 (ver `docs/COMPATIBILITY.md`).

## Instalar

| Alcance | Windows (PowerShell) | macOS / Linux |
|---|---|---|
| Personal (global) | `.\install.ps1 -Client claude -Scope global` → `%USERPROFILE%\.claude\skills\security-compliance` | `./install.sh --client claude --scope global` → `~/.claude/skills/security-compliance` |
| Proyecto | `.\install.ps1 -Client claude -Scope project -ProjectPath C:\repos\mi-app` → `<proyecto>\.claude\skills\security-compliance` | `./install.sh --client claude --scope project --project-path /repos/mi-app` |

Precedencia ante el mismo nombre: Enterprise > Personal > Proyecto. Use una sola instalación.

## Verificar el descubrimiento

En una sesión nueva escriba `/` y busque `security-compliance`, o ejecute `/security-compliance help`. Claude Code detecta cambios de skills existentes durante la sesión, pero un directorio de skills creado después del arranque requiere reiniciar.

## Uso

- Manual: `/security-compliance help` · `/security-compliance diff` · `/security-compliance audit` · `/security-compliance sox`.
- Lenguaje natural: «Usá el skill security-compliance para revisar los cambios actuales…».
- Los argumentos (`diff`, `audit`…) llegan al skill como texto del mensaje; el skill resuelve comando, raíz y alcance antes de ejecutar nada.
- **Solo manual:** `--invocation manual` agrega `disable-model-invocation: true` (la descripción deja de cargarse en el contexto y Claude no lo invoca solo).
- El runner se ubica con `${CLAUDE_SKILL_DIR}`; Claude puede pedir permiso para ejecutar `python3 …/sc.py`. No se pre-aprueban herramientas (`allowed-tools` no se usa).

## Actualizar / desinstalar

```powershell
.\install.ps1 -Client claude -Scope global -Update
.\install.ps1 -Client claude -Scope global -Uninstall
```

```bash
./install.sh --client claude --scope global --update
./install.sh --client claude --scope global --uninstall
```

## Límites

- Hooks de Claude Code: **no implementados** (extensión opcional pendiente). No se tocan `CLAUDE.md` ni `settings.json`.
- Validación dentro de Claude Code: ver `docs/VALIDATION.md` (sección «Validación dentro de clientes»).
