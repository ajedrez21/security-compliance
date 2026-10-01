# Flujo de revisión, gate y configuración

## Flujo recomendado

1. **Resumen previo** (2-3 líneas): comando, raíz, configuración (¿existe `.security-compliance.yml`?), alcance.
2. **Runner**: `sc.py <comando>` produce `report.json`, `report.md`, `inventory.json`, `SHA256SUMS` y `tool-output/` en `<salida>/<run-id>/` (nunca se sobrescribe una ejecución previa).
3. **Revisión asistida** de los controles `agent` pendientes (ver SKILL.md §3) → `review.json`.
4. **Reimportar**: mismo comando con `--review review.json`. El `snapshot_hash` de la revisión debe coincidir con el snapshot actual; si no, queda rechazada y los controles siguen sin verificar.
5. **Presentar** el Markdown: qué se revisó, qué se encontró, qué bloquea, qué falta comprobar y cómo resolverlo.

`report --run <dir>` solo re-renderiza una ejecución: no escanea ni cambia conclusiones.

## Alcance Git (`diff` / `pr`)

- Sin `--base`: staged + unstaged + untracked contra `HEAD` (no incluye commits ya hechos en la rama).
- Con `--base X`: árbol de trabajo contra `merge-base(X, HEAD)`; incluye commits propios, staged, unstaged y untracked.
- Repositorio sin commits: todo cuenta como nuevo. Detached HEAD, renombres, borrados, espacios y Unicode se soportan.
- Base inexistente o clone superficial: error accionable (el skill no hace `fetch` por sí solo ni inventa un diff).
- Si HEAD, el índice o los archivos cambian durante la revisión → snapshot inconsistente → gate `INCOMPLETE`.
- Sin comparación contra una baseline real, `baseline_status` queda `unknown` (no se afirma "introducido por el cambio").

## Estados y gate

| Gate | Condición |
|---|---|
| `BLOCKED` | Hallazgos confirmables (confianza no baja, origen no heurístico) con severidad ≥ umbral, controles obligatorios en `FAIL`, u obligatorios sin verificar con `unknown_required: block`. |
| `INCOMPLETE` | Sin bloqueo demostrado, pero hay controles seleccionados `UNKNOWN`/`NOT_RUN`/`ERROR`, alcance vacío, snapshot inconsistente o ningún control evaluable. |
| `PASS_WITH_WARNINGS` | Todo lo requerido completo y aprobado, con hallazgos no bloqueantes o advertencias residuales. |
| `PASS` | Verificaciones completas y satisfechas para el alcance evaluado. |

Precedencia: `BLOCKED` > `INCOMPLETE` > `PASS_WITH_WARNINGS` > `PASS`. Exit codes (solo `enforce`): `1` bloqueo, `3` incompleto, `0` resto; error técnico/configuración `2` (precedencia 2 > 1 > 3 > 0). En `advisory` siempre `0` (salvo error técnico) y el gate real queda en el JSON.

## Configuración (`.security-compliance.yml`, opcional)

Precedencia: defaults → configuración del proyecto → flags. En `enforce` una **política confiable externa** (`--policy`) prevalece para `gate`, `paths`, `trust`, `itgc`, `project` y excepciones; el PR no puede rebajarla. El YAML se valida contra `schemas/config.schema.json`: se rechazan YAML inseguro (anclas, tags), claves desconocidas, campos ejecutables (`command`, `script`, `hooks`…) y rutas que escapen del proyecto. El reporte incluye la configuración efectiva y su hash.

`asvs_target_level` es un objetivo de **selección**, no una certificación ni cobertura completa.

## Excepciones

Solo vienen de la configuración/política con `id`, `reason`, `owner`, `expires` (fecha), `scope` y `origin`. Vencidas se ignoran. **Nunca** las crees para obtener un gate verde ni inventes su aprobación.
