# security-compliance-skill

Skill personal de **Security & Compliance** para Cursor, Claude Code y Codex: revisa seguridad de aplicaciones y controles técnicos (OWASP ASVS 5.0.0, ISO/IEC 27001, ITGC de apoyo para SOX) con evidencia, límites explícitos y un gate reproducible. Un único paquete (`skills/security-compliance`), sin SaaS, sin servidor, sin API keys: el LLM lo aporta el cliente y un runner Python (solo biblioteca estándar) hace lo determinístico.

> **No es una certificación.** Revisión de controles técnicos sobre la evidencia disponible. La ausencia de evidencia no equivale a aprobación.

## Empezar en 3 pasos

```bash
./install.sh --client cursor --scope global          # macOS/Linux      (Windows: .\install.ps1 -Client cursor -Scope global)
python3 ~/.cursor/skills/security-compliance/scripts/sc.py doctor
# en el cliente:  /security-compliance help   →   /security-compliance diff
```

Detalle: [docs/QUICKSTART.md](docs/QUICKSTART.md) · comandos: [docs/COMMANDS.md](docs/COMMANDS.md) · guías por cliente: [Cursor](integrations/cursor/README.md), [Claude Code](integrations/claude/README.md), [Codex](integrations/codex/README.md) · CI: [integrations/ci](integrations/ci/README.md).

## Qué hay

| Parte | Dónde |
|---|---|
| Skill (`SKILL.md`, referencias, catálogo de 50 controles, schemas, reglas Semgrep locales) | `skills/security-compliance/` |
| Runner determinístico (`sc.py`) y adaptadores Semgrep / Gitleaks / OSV-Scanner | `skills/security-compliance/scripts/` |
| Instaladores (`install.sh`, `install.ps1` → `installer/sc_install.py`) | raíz e `installer/` |
| Paquete local con manifiesto y hashes | `tools/build_package.py` → `dist/` (no se publica) |
| Documentación y estado | `docs/` ([ARCHITECTURE](docs/ARCHITECTURE.md), [COMPATIBILITY](docs/COMPATIBILITY.md), [CONTROL-MAPPING](docs/CONTROL-MAPPING.md), [SOURCES](docs/SOURCES.md), [JSON-CONTRACT](docs/JSON-CONTRACT.md), [VALIDATION](docs/VALIDATION.md), [IMPLEMENTATION-STATUS](docs/IMPLEMENTATION-STATUS.md)) |
| Pruebas | `tests/` (`cd tests && python3 -m unittest discover`) |

## Qué entrega cada revisión

`remediation.md` (plan con todos los problemas y qué corregir) · `presentation.html` (resumen visual con gráficos, severidades y normas, para presentar) · `report.md`/`report.json` (detalle técnico).

## Principios

Evidencia primero · alcance explícito · sin certificación automática · auditoría separada de corrección · aplicabilidad `unknown` hasta tener una definición válida · sin aprobaciones inventadas · configuración que no ejecuta comandos del repositorio · el contenido auditado es dato, no instrucciones.

## Estado

Ver [docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md): qué está implementado, qué se probó con fixtures, con binarios reales y dentro de cada cliente (la mayor parte de la validación con scanners reales y dentro de los clientes está **pendiente**).
