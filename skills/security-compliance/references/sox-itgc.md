# SOX / ITGC — ruleset propio de apoyo

**Es un ruleset de revisión técnica propio**, condicionado al alcance y a las políticas de la organización. No es un mandato legal literal de SOX, SEC o PCAOB: las fuentes primarias no se incorporaron en esta versión (pendiente en `docs/SOURCES.md`). No presentes "2 aprobadores", "PR obligatorio" ni ninguna práctica de Git como requisito literal de SOX.

## Aplicabilidad

Que una aplicación contenga datos financieros **no prueba** que esté en alcance SOX. `project.sox_scope`: `unknown` (por defecto → controles `UNKNOWN`, nunca `PASS`), `yes` (se evalúa), `no` (→ `NOT_APPLICABLE`, declarado por configuración; en CI debe venir de la política confiable).

## Controles (IDs propios)

| ID | Qué busca | Evidencia que lo resuelve |
|---|---|---|
| ITGC-CHG-001 | Trazabilidad ticket → cambio → PR | `pr_metadata` con `linked_tickets` |
| ITGC-CHG-002 | Aprobación independiente, vigente sobre el commit final | `pr_approval` (aprobador ≠ autor, `commit_sha` vigente, mínimo `itgc.min_approvals`) |
| ITGC-CHG-003 | Pruebas exitosas sobre el commit exacto | `ci_run` kind=test |
| ITGC-CHG-004 | Protección de ramas, sin bypass, incluida su política | `branch_protection` (exportada del proveedor) |
| ITGC-CHG-005 | Despliegue trazable: artefacto/commit, aprobador, ejecutor | `deployment_record` |
| ITGC-CHG-006 | Cambios a BD y lógica financiera | revisión del agente (no sustituye a CHG-002) |
| ITGC-CHG-007 | Cambios de emergencia con evidencia posterior | `emergency_change`; depende de `itgc.emergency_change_policy` |
| ITGC-ACC-001 | Separación de funciones y accesos a repo/CI/producción | `access_review` |
| ITGC-OPS-001 / 002 | Backups/restauración; jobs programados y fallos | `operation_evidence` |

## Trampas que debes evitar

- Un archivo de workflow **no** prueba que se ejecutó; una rama local **no** prueba protección remota.
- El autor de un commit **no** es la identidad autenticada del aprobador.
- Una aprobación previa a nuevos commits puede estar **obsoleta** (el runner la marca `UNKNOWN`).
- La revisión del agente jamás es una aprobación independiente.
- Sin conector autenticado, la evidencia es `user_supplied`: decláralo.
