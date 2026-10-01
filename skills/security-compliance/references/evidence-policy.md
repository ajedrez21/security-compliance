# Política de evidencia

## Procedencia (de menor a mayor confianza posible)

| Procedencia | Significado | Puede producir `PASS` |
|---|---|---|
| `heuristic` | Coincidencia por regex del runner (solo hallazgos) | Nunca; no bloquea el gate; no reemplaza un scanner |
| `agent_review` | Tu revisión estructurada importada | Solo controles de método `agent`; con `files_examined` |
| `local_observation` | Hecho verificable localmente (lockfile presente, `USER` en Dockerfile) | Controles de método `local` |
| `scanner` | Salida normalizada de Semgrep/Gitleaks/OSV-Scanner con versión y alcance | Controles de método `scanner` |
| `user_supplied` | Evidencia de PR/CI/proceso aportada en un archivo | Controles de método `evidence`, si la política confía (`trust.user_supplied_evidence`) |
| `provider_verified` | Verificada por un conector autenticado del proveedor | **No implementado en v1**: una afirmación `provider_verified` dentro de un archivo se degrada a `user_supplied` |

Una URL en la evidencia no la vuelve verificada.

## Validación al importar (`--evidence`)

Se valida: schema; pertenencia al repositorio (`project.repo` o remoto `origin`); correspondencia del `commit_sha` con HEAD (evidencia ligada al commit: `pr_metadata`, `pr_approval`, `ci_run`, `deployment_record`); temporalidad (no anterior al commit evaluado ni en el futuro); cambios locales no cubiertos por el commit. Resultado por ítem: `accepted`, `non_conclusive` (se ignora para PASS y queda `UNKNOWN`) o `rejected` (otro repositorio).

## Tipos

`pr_metadata`, `pr_approval`, `ci_run` (`details.kind`: test/security; `details.conclusion`), `branch_protection`, `deployment_record`, `change_ticket`, `access_review`, `operation_evidence`, `emergency_change`, `organizational`. Ejemplo: `assets/evidence.example.json` (sintético).

## Revisión del agente (`--review`)

Se vincula por `snapshot_hash` (o `head_sha` con árbol limpio). Se rechazan: control inexistente/no seleccionado, `FAIL` sin hallazgo, `PASS` sin `files_examined`, hallazgos sobre archivos que no existen en el snapshot o líneas fuera de rango, y resultados para controles que solo admiten scanner/evidencia. En `enforce`, una revisión aportada con el cambio solo cuenta si la política confiable lo permite (`trust.agent_review`).
