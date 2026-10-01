# Compatibilidad con clientes

Fecha de verificación: **2026-09-30** (consulta de la documentación oficial vigente ese día).

## Rutas de instalación y descubrimiento

| Cliente | Global | Proyecto | Fuente | Versión del cliente en la máquina de desarrollo |
|---|---|---|---|---|
| Cursor | `~/.cursor/skills/` (también lee `~/.agents/skills/`, `~/.claude/skills/`, `~/.codex/skills/`) | `.cursor/skills/` (también `.agents/skills/`, `.claude/skills/`, `.codex/skills/`) | https://cursor.com/docs/skills | 3.16.17 |
| Claude Code | `~/.claude/skills/` (Personal) | `.claude/skills/` (Proyecto); Enterprise por política administrada; anidados `<subdir>/.claude/skills/` | https://code.claude.com/docs/en/skills | 2.1.195 |
| Codex | `$HOME/.agents/skills/`; admin `/etc/codex/skills/` | `.agents/skills/` desde el cwd hasta la raíz del repo | https://developers.openai.com/codex/skills → https://learn.chatgpt.com/docs/build-skills | codex-cli 0.142.3 |

Elección del instalador: Cursor → `.cursor/skills`; Claude → `.claude/skills`; Codex → `.agents/skills`. Cursor y Codex comparten `.agents/skills` (instalar ambos allí produce una instalación duplicada, que se informa sin borrar).

## Sintaxis de invocación

| Cliente | Manual | Fuente |
|---|---|---|
| Cursor | `/` en el chat del Agent y elegir el skill (`/security-compliance`) | docs de Cursor |
| Claude Code | `/security-compliance <argumentos>` | docs de Claude Code |
| Codex | `$security-compliance` (CLI/IDE); `@security-compliance` (ChatGPT) | docs de Codex |

No se promete que la sintaxis sea idéntica entre clientes; el lenguaje natural funciona en todos.

## Control del descubrimiento (modo manual estricto)

| Cliente | Mecanismo real | Efecto | Límite |
|---|---|---|---|
| Cursor | `disable-model-invocation: true` en el frontmatter | Solo aparece con `/skill-name` | Controla la selección por el agente, no obliga a ejecutarlo |
| Claude Code | `disable-model-invocation: true` | La descripción no se carga en el contexto; solo el usuario lo invoca | ídem |
| Codex | `agents/openai.yaml` → `policy.allow_implicit_invocation: false` | El `$skill` explícito sigue funcionando | Cursor también lee `.agents/skills` y no usa ese archivo |

Un skill **nunca** hace obligatoria una revisión: eso requiere CI, protección de ramas o hooks fuera del skill.

## Frontmatter

Se usan solo campos de la especificación Agent Skills (`name`, `description`, `compatibility`, `metadata`) más `disable-model-invocation` únicamente en la copia instalada en modo manual (campo soportado por Cursor y Claude Code). Validado por `skillcheck.py` contra https://agentskills.io/specification (nombre 1-64, minúsculas/números/guiones, igual al directorio; `description` ≤ 1024 caracteres). No se validó con la herramienta de referencia `skills-ref` (no instalada).

## Validación realizada

Ver `docs/VALIDATION.md`: la instalación en rutas temporales se probó en macOS; el **descubrimiento dentro de Codex 0.142.3 se validó** (`$security-compliance help` y `diff`); Cursor y Claude Code siguen pendientes. Windows: scripts escritos y revisados, **no ejecutados** (no hay Windows ni PowerShell en la máquina de desarrollo).

## Qué no se verificó

Precedencia entre skills homónimos en Cursor (no documentada en lo consultado); comportamiento exacto de `$ARGUMENTS`/paso de argumentos en cada cliente más allá de lo documentado; hooks de ningún cliente (no implementados).
