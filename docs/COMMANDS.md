# Guía de comandos

Todos los comandos existen como **vocabulario del skill** (invocación `/security-compliance <comando>` o lenguaje natural) y como **CLI determinístico** (`python <skill>/scripts/sc.py <comando>`). Sintaxis por cliente: Cursor/Claude Code `/security-compliance <comando>`, Codex `$security-compliance <comando>`.

| Comando | Skill (asistido) | CLI (determinístico) | Modifica el proyecto |
|---|---|---|---|
| `help` | Muestra ayuda corta; **no inicia** una auditoría. Sugiere `diff` si hay cambios, `audit` si no. | `sc.py help [all]` | No |
| `doctor` | Diagnostica instalación y capacidades | `sc.py doctor --project .` | No |
| `init` | Detecta stack, pregunta solo lo no deducible, crea la configuración | `sc.py init --project . [--sox-scope …]` | Solo crea `.security-compliance.yml` |
| `audit` | Revisión completa + análisis del agente de los controles pendientes | `sc.py audit --project . --output DIR` | No |
| `diff` | Revisa cambios (staged, unstaged, untracked; con `--base` desde el merge-base) leyendo el contexto necesario | `sc.py diff --project . --base main` | No |
| `pr` | `diff` + evidencia de PR/CI importada; head SHA validado | `sc.py pr --project . --base main --head SHA --evidence ev.json` | No |
| `sox` | Controles ITGC de apoyo; `unknown` si el alcance SOX no está definido | `sc.py sox --project . [--evidence ev.json]` | No |
| `iso` | Controles técnicos relacionados con ISO/IEC 27001 | `sc.py iso --project .` | No |
| `security` | Seguridad de aplicación con mappings ASVS | `sc.py security --project .` | No |
| `secrets` | Scanner de secretos + revisión acotada; nunca muestra valores | `sc.py secrets --project .` | No |
| `dependencies` | Inventario y vulnerabilidades (red solo si se permite) | `sc.py dependencies --project .` | No |
| `report` | Muestra/exporta una ejecución sin repetir escaneos ni cambiar conclusiones | `sc.py report --run DIR/<run-id> [--format md\|json\|html\|remediation] [--out archivo]` | No |

## Opciones del CLI

`--project DIR` · `--config FILE` · `--output DIR` · `--mode advisory|enforce` · `--policy FILE` · `--allow-project-policy` · `--review FILE` · `--evidence FILE` (repetible) · `--base REF` · `--head SHA` · `--timeout SEG` · `--json` (reporte en stdout) · `--non-interactive`. Argumentos inválidos → código `2` con mensaje.

## Códigos de salida

| Código | Significado |
|---|---|
| `0` | Ejecución aceptable según el modo (en `advisory` siempre, salvo error técnico) |
| `1` | Bloqueo de política (solo `enforce`) |
| `2` | Error de configuración / runtime / argumentos (YAML inválido, política interna en enforce, base inexistente…) |
| `3` | Evaluación incompleta (solo `enforce`) |

Precedencia: `2 > 1 > 3 > 0`. En `advisory`, el JSON conserva el gate real (`gate.status`).

## Ejemplos (manual y lenguaje natural)

```text
/security-compliance help
/security-compliance init
/security-compliance diff
/security-compliance audit
/security-compliance sox
Usá el skill security-compliance para revisar los cambios actuales. Priorizá autorización, secretos y cambios de base de datos.
Generá un reporte con evidencia y controles que no pudiste verificar.
```

## Flujo de la revisión asistida

1. El agente ejecuta el comando → obtiene `snapshot_hash`, archivos cambiados y controles pendientes.
2. Analiza los controles `agent` siguiendo el `review_procedure` del catálogo y escribe `review.json` (`assets/review.example.json`).
3. Reimporta: `sc.py diff --project . --review review.json`. La revisión conserva la procedencia `agent_review`; se rechaza si el snapshot no coincide.

## Archivos que genera cada ejecución (`<salida>/<run-id>/`)

| Archivo | Para qué |
|---|---|
| `remediation.md` | **Plan de remediación**: todos los problemas ordenados por severidad, con checklist, qué pasa, riesgo, qué hacer, normas relacionadas, y lo pendiente de verificar |
| `presentation.html` | **Presentación visual** autocontenida (sin JavaScript ni recursos externos; claro/oscuro; imprimible): resumen, gráficos por severidad/estado/dominio, criterios de severidad, normas (ASVS, ISO, SOX) y detalle de cada problema |
| `report.md` / `report.json` | Detalle técnico y contrato JSON |
| `inventory.json`, `SHA256SUMS`, `tool-output/` | Alcance con hashes, integridad y salida normalizada de scanners |

Revisar **todo el código y también los cambios**: `audit` (todo el alcance) y `diff` (solo lo cambiado) son ejecuciones separadas, cada una con sus archivos.

## Seguimiento al corregir (el reporte se actualiza)

1. Corregí los problemas del `remediation.md`.
2. Repetí el **mismo comando** con la **misma carpeta de salida** (por defecto `.security-compliance/reports`). Si usás el agente, pedile que repita la revisión de lo que cambió.
3. El nuevo `remediation.md` / `presentation.html` incluye **Progreso** respecto de la ejecución anterior del mismo comando y proyecto:

| Categoría | Significado |
|---|---|
| ✅ Resuelto | Su control se volvió a verificar y el hallazgo ya no aparece |
| Persiste | Sigue apareciendo (aunque haya cambiado de línea) |
| 🆕 Nuevo | Aparece ahora y antes no |
| ❓ Sin reverificar | Su control no se pudo evaluar esta vez (falta repetir la revisión del agente o un scanner): **no** se afirma que se corrigió; se sigue arrastrando |

Además se muestra la evolución entre revisiones (hasta 20) y se actualizan las copias `latest-<comando>-remediation.md` y `latest-<comando>-presentation.html` en la carpeta de salida. Las ejecuciones previas nunca se sobrescriben. Un reporte previo ilegible se ignora sin romper la nueva ejecución.
