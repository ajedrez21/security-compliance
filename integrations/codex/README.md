# Codex (OpenAI)

Rutas y sintaxis verificadas contra la documentación de Skills de Codex (https://developers.openai.com/codex/skills, hoy redirige a https://learn.chatgpt.com/docs/build-skills) el 2026-09-30 (ver `docs/COMPATIBILITY.md`).

## Instalar

| Alcance | Windows (PowerShell) | macOS / Linux |
|---|---|---|
| Usuario (global) | `.\install.ps1 -Client codex -Scope global` → `%USERPROFILE%\.agents\skills\security-compliance` | `./install.sh --client codex --scope global` → `~/.agents/skills/security-compliance` |
| Repositorio | `.\install.ps1 -Client codex -Scope project -ProjectPath C:\repos\mi-app` → `<repo>\.agents\skills\security-compliance` | `./install.sh --client codex --scope project --project-path /repos/mi-app` |

Codex lee `.agents/skills` desde el directorio de trabajo hasta la raíz del repositorio, `$HOME/.agents/skills` y `/etc/codex/skills`. **Cursor también lee `.agents/skills`**: si instala para ambos clientes en el mismo alcance, verá un aviso de instalación duplicada (no se borra nada).
Los skills homónimos de distintos alcances no se fusionan: ambos aparecen en el selector.

## Verificar el descubrimiento

Reinicie Codex y ejecute `$security-compliance help` (CLI/IDE; en ChatGPT: `@security-compliance`). Debe mostrar la ayuda corta.

## Uso

- Manual: `$security-compliance help` · `$security-compliance diff` · `$security-compliance audit` · `$security-compliance sox`.
- Lenguaje natural: «Usá el skill security-compliance para revisar los cambios actuales…».
- **Solo manual:** `--invocation manual` crea `agents/openai.yaml` con `policy.allow_implicit_invocation: false` (el `$skill` explícito sigue funcionando).

## Actualizar / desinstalar

```powershell
.\install.ps1 -Client codex -Scope global -Update
.\install.ps1 -Client codex -Scope global -Uninstall
```

```bash
./install.sh --client codex --scope global --update
./install.sh --client codex --scope global --uninstall
```

## Límites

- Configuración `agents/openai.yaml` de interfaz (iconos, `default_prompt`) no se genera; solo la política de invocación en modo manual.
- Validado en `codex-cli` 0.142.3 (instalación por proyecto): `$security-compliance help` y `$security-compliance diff` funcionan; ver `docs/VALIDATION.md`. En el sandbox `workspace-write` Semgrep puede fallar por certificados (se reporta como `ERROR`, no `PASS`).
