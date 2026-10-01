# Changelog

## 1.0.0 — 2026-09-30

Primera versión (SC-001).

- Skill `security-compliance` (SKILL.md, 8 referencias por stack, 7 referencias de marco/flujo, plantillas y ejemplos sintéticos).
- Catálogo 1.0.0: 50 controles (30 `SEC-*`, 10 `ITGC-*`, 10 `ISO-*`); baseline ASVS 5.0.0 con IDs verificados (80 de 345 referenciados).
- Runner `sc.py`: `help`, `doctor`, `init`, `audit`, `diff`, `pr`, `sox`, `iso`, `security`, `secrets`, `dependencies`, `report`.
- Adaptadores Semgrep (reglas locales), Gitleaks y OSV-Scanner; heurísticas y comprobaciones locales etiquetadas por origen.
- Importación validada de evidencia de PR/CI y de la revisión estructurada del agente; gate `PASS/PASS_WITH_WARNINGS/BLOCKED/INCOMPLETE` con códigos de salida 0/1/2/3.
- Reportes JSON (schema) y Markdown por `run_id`, con SHA256SUMS.
- Instalador (Cursor, Claude Code, Codex; global/proyecto; manual/asistido; update con rollback; uninstall seguro) y paquete local determinístico.
- Plan de remediación (`remediation.md`) y presentación HTML autocontenida (`presentation.html`) en cada ejecución; `report --format html|remediation`.
- Seguimiento de progreso entre ejecuciones (`progress`, `history`): resueltos / persistentes / nuevos / sin reverificar, evolución y copias `latest-*`.
- Ejemplo de CI (`gate.sh` + política confiable + workflow de GitHub Actions no ejecutado).
