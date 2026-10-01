# Contrato JSON para integraciones externas

Schemas (JSON Schema draft 2020-12, subconjunto soportado por el validador del runner): `skills/security-compliance/schemas/`.
`report.schema.json` es autocontenido (finding y mapping incluidos); `schema_version: 1`. Un consumidor externo puede validar con cualquier librería JSON Schema.

| Schema | Descripción |
|---|---|
| `config.schema.json` | `.security-compliance.yml` y política confiable (`--policy`) |
| `report.schema.json` | Reporte de una ejecución (`report.json`) |
| `finding.schema.json` | Hallazgo normalizado |
| `evidence.schema.json` | Evidencia importada (`--evidence`) |
| `review.schema.json` | Revisión estructurada del agente (`--review`) |

## Reporte (`report.json`) — campos principales

`run_id`, `generated_at` (UTC), `command`, `mode`, `skill.version`, `catalog.version/baselines`, `project` (nombre, raíz saneada, repo, git: head/branch/base/merge_base/dirty), `snapshot` (`snapshot_hash` de contenido, `snapshot_hash_end`, conteos, `consistent`, `scope`, `changed_files`, `exclusions`), `config` (`hash`, `policy_source` = `defaults|project_config|trusted_policy`, configuración efectiva), `stacks`, `controls[]` (estado, motivo, fuente, procedencia, hallazgos y evidencia vinculados), `findings[]`, `scanners[]` (herramienta, versión, estado, duración, comando saneado, alcance, reglas, exclusiones), `evidence`, `agent_review`, `coverage`, `gate`, `exceptions`, `limitations`, `warnings`, `disclaimer`.

## Semántica

- **Estados de control:** `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`, `NOT_RUN`, `ERROR`. **Gate:** `PASS`, `PASS_WITH_WARNINGS`, `BLOCKED`, `INCOMPLETE` (+ `exit_code` ∈ {0,1,3}; el código 2 es error técnico y no genera reporte).
- **Hallazgo:** `origin` ∈ `scanner|heuristic|local_observation|agent_review|user_supplied|provider_verified`; `confidence` ∈ `high|medium|low`; `baseline_status` es `unknown` salvo comparación real; `in_scope` indica si cuenta para el gate (en `diff`/`pr`, solo archivos cambiados).
- **Evidencia:** `provenance` es la efectiva; `provenance_declared` la que traía el archivo; `validation.status` ∈ `accepted|non_conclusive|rejected`.
- **Snapshot:** hash sobre `(ruta, sha256 del contenido)` ordenado de los archivos en alcance; no depende solo del SHA de HEAD.
- El JSON sin firma: `SHA256SUMS` detecta cambios accidentales, **no** es una firma ni cadena de custodia.

## Ejemplos sintéticos

`assets/review.example.json`, `assets/evidence.example.json`, `assets/config.example.yml`. Un reporte de ejemplo se obtiene con `sc.py audit` sobre cualquiera de los fixtures de `tests/fixtures/`.

## Derivados de presentación

`remediation.md` y `presentation.html` se generan **desde** `report.json` (no recalculan conclusiones) y también con `sc.py report --run DIR --format remediation|html`.

## Progreso

`progress` (comparación con la ejecución anterior del mismo comando/proyecto: `resolved`, `persistent`, `new`, `not_reverified`, `control_changes`, conteos y gates antes/después) e `history` (resumen de hasta 19 ejecuciones previas). Un hallazgo es `resolved` solo si su control se reverificó; la identidad de un hallazgo no depende del número de línea ni (en revisiones del agente) del cliente o la redacción.
