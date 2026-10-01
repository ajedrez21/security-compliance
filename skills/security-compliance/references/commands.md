# Comandos y sintaxis por cliente

## Vocabulario común

| Comando | Qué hace | Modifica el proyecto |
|---|---|---|
| `help` | Muestra comandos, ejemplos, modalidades y límites. Sin scanners. | No |
| `doctor` | Diagnostica instalación, runtime, scanners, configuración y capacidades. No instala nada. | No |
| `init` | Detecta el stack y crea `.security-compliance.yml` mínimo (no pisa uno existente). | Solo crea ese archivo |
| `audit` | Revisión completa: marcos configurados, scanners, evidencia y revisión del agente. | No (escribe reportes en la salida) |
| `diff` | Cambios staged + unstaged + untracked; con `--base` incluye commits desde el merge-base. | No |
| `pr` | `diff` + evidencia de PR/CI importada (`--evidence`); head SHA validado. | No |
| `sox` | Controles ITGC de apoyo; aplicabilidad `unknown` hasta definir `project.sox_scope`. | No |
| `iso` | Controles técnicos relacionados con ISO/IEC 27001. | No |
| `security` | Seguridad de aplicación (catálogo + mappings ASVS). | No |
| `secrets` | Scanner de secretos + heurísticas; nunca imprime valores. | No |
| `dependencies` | Inventario y vulnerabilidades de dependencias (red solo si se permite). | No |
| `report` | Muestra/exporta una ejecución existente sin repetir escaneos ni cambiar conclusiones. | No |

Invocar el skill **sin argumento** muestra ayuda corta y sugiere `diff` (si hay cambios) o `audit`; no inicia una auditoría.

## Invocación manual por cliente (sintaxis verificada en la documentación vigente; ver docs/COMPATIBILITY.md)

| Cliente | Manual (explícita) | Lenguaje natural |
|---|---|---|
| Cursor | `/security-compliance diff` (escribir `/` en el chat del Agent y elegir el skill) | "Usá el skill security-compliance para revisar los cambios actuales." |
| Claude Code | `/security-compliance diff` | igual |
| Codex | `$security-compliance diff` (CLI/IDE; en ChatGPT `@security-compliance`) | igual |

La selección asistida (el agente elige el skill por contexto) no está garantizada. Los controles **obligatorios** pertenecen a CI, protección de ramas o hooks configurados fuera del skill.

## Lenguaje natural (siempre disponible)

```text
Usá el skill security-compliance para revisar los cambios actuales.
Priorizá autorización, secretos y cambios de base de datos.
Generá un reporte con evidencia y controles que no pudiste verificar.
```

## CLI determinístico

```bash
python3 <skill-dir>/scripts/sc.py help [all]
python3 <skill-dir>/scripts/sc.py doctor --project .
python3 <skill-dir>/scripts/sc.py init --project . [--sox-scope unknown|yes|no] [--update-gitignore]
python3 <skill-dir>/scripts/sc.py diff --project . [--base main] [--review review.json] [--json]
python3 <skill-dir>/scripts/sc.py audit --project . --output ./audit-output
python3 <skill-dir>/scripts/sc.py pr --project . --base main --head <sha> --evidence pr-evidence.json
python3 <skill-dir>/scripts/sc.py report --run ./audit-output/<run-id> [--format json|md] [--out archivo]
```

Opciones comunes: `--project`, `--config`, `--output`, `--mode advisory|enforce`, `--policy`, `--allow-project-policy`,
`--review`, `--evidence` (repetible), `--base`, `--head`, `--timeout`, `--json`, `--non-interactive`.
Códigos de salida: `0` aceptable según el modo · `1` bloqueo (enforce) · `2` error de configuración/runtime · `3` incompleto (enforce).
