# CI: gate obligatorio basado en el CLI

**Estado:** ejemplo funcional probado de forma local (script `gate.sh` + política; ver `tests/test_gate.py`). El workflow de GitHub Actions (`github-actions.example.yml`) **no se ejecutó en GitHub** y no está activado; los marcadores `<…>` deben completarse.

## Piezas

| Archivo | Rol |
|---|---|
| `gate.sh` | Ejecuta `sc.py pr --mode enforce --policy …`, conserva los reportes y propaga el código de salida |
| `policy.example.yml` | Política confiable de ejemplo (umbrales, controles requeridos, confianza) |
| `github-actions.example.yml` | Workflow de ejemplo (checkout del PR + política de la rama base + skill fijado) |

## Códigos de salida

`0` aceptable · `1` bloqueo de política · `2` error de configuración/runtime (p. ej. política dentro del proyecto) · `3` evaluación incompleta (controles sin verificar). Precedencia: 2 > 1 > 3 > 0.

## Política confiable

- En `--mode enforce` el CLI **exige** `--policy` y rechaza una política dentro del árbol auditado.
- La política prevalece para `gate`, `paths`, `itgc`, `trust`, `project` (alcance SOX, repo), `frameworks` y excepciones. Un PR que edite `.security-compliance.yml` para bajar umbrales, excluir rutas, declararse fuera de alcance SOX o autoaprobar excepciones **no** logra efecto (probado).
- Una revisión del agente o evidencia `user_supplied` aportada con el cambio solo cuenta si la política lo permite (`trust.*`; por defecto no).

## Obligatoriedad real

Un archivo de workflow no es obligatorio por sí solo. Requiere: (1) marcar el check como requerido en la protección de rama del proveedor, (2) restringir quién puede editar el workflow y la política, (3) revisar CODEOWNERS sobre esos archivos. **Esta entrega no configuró nada de eso.**

## Seguridad al procesar PRs no confiables

Use `pull_request` (no `pull_request_target`), permisos `contents: read`, sin secretos, sin credenciales persistidas, acciones fijadas por SHA, y scanners con versiones fijadas. El skill no ejecuta código del proyecto auditado.

## Otros CI (GitLab, Azure DevOps, Jenkins)

El patrón es el mismo: (1) clonar el PR con historial suficiente, (2) obtener la política de la rama base/otro repositorio a un directorio **fuera** del árbol auditado, (3) `sh gate.sh <skill> <proyecto> <política> <salida> <base>`, (4) fallar el job con el código devuelto, (5) publicar `<salida>` como artefacto y (6) marcar el job como requerido en el proveedor. Para evidencia de PR/CI exporte los datos del proveedor al formato `evidence.schema.json` y páselos con `--evidence` (el skill no verifica su autenticidad; no hay conectores en v1).
