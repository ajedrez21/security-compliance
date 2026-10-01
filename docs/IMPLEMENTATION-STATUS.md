# Estado de implementación y handoff

Versión 1.0.0 · actualizado 2026-10-01 · especificación: `TAREA_Security_Compliance_Skill.md` (SC-001 v1.0)

Leyenda: ✅ implementado y probado con fixtures + código real · 🧪 probado solo con simulaciones (fakes) · ⏳ pendiente · ➖ opcional no implementado.

## Etapas

| Etapa | Estado | Notas |
|---|---|---|
| E1 — Diseño ejecutable | ✅ | Fuentes verificadas (`SOURCES.md`, `COMPATIBILITY.md`); decisiones en `ARCHITECTURE.md`; sin dependencias de BYF |
| E2 — Skill utilizable | ✅ | `SKILL.md`, 15 referencias, catálogo (50 controles), plantillas y ejemplos sintéticos |
| E3 — Runner | ✅ | Runner probado; adaptadores probados con fakes y con binarios reales (Semgrep 1.176.0, Gitleaks 8.30.1, OSV-Scanner 2.6.0) |
| E4 — Distribución | ✅ (macOS) / ⏳ (Windows, Linux) | Instalador, ciclo de vida, `doctor`, paquete local determinístico |
| E5 — Integración | ✅ / ⏳ | Guías de los 3 clientes; CI: `gate.sh` probado localmente, workflow de Actions no ejecutado |
| E6 — Validación | ✅ parcial | `VALIDATION.md`: ver pendientes |

## Checklist del alcance obligatorio (§3.1)

| Requisito | Estado |
|---|---|
| Paquete canónico `security-compliance` (SKILL.md + recursos bajo demanda) | ✅ |
| Instalación, actualización explícita, desinstalación y diagnóstico | ✅ |
| Cursor, Claude Code, Codex; global y por proyecto | ✅ rutas verificadas en documentación; ✅ validado dentro de **Codex** (help + diff con revisión importada); ⏳ Cursor y Claude Code |
| Documentación de invocación manual y asistida | ✅ |
| Comandos `help doctor init audit diff pr sox iso security secrets dependencies report` | ✅ |
| Configuración opcional validada y versionada (schema) | ✅ |
| Revisión asistida con controles y criterios de evidencia | ✅ (procedimiento por control; revisión importable) |
| Runner: inventario, scanners, normalización, reportes, gate | ✅ |
| Adaptadores SAST (Semgrep), secretos (Gitleaks), dependencias (OSV-Scanner) | ✅ probados con binarios reales (limpio y hallazgos); 🧪 timeout/JSON inválido/error solo con fakes |
| Importación validada de evidencia de PR/CI | ✅ |
| Reportes Markdown y JSON, schemas, catálogo, pruebas | ✅ |
| Referencias de stack (.NET, Node/Nest/Express, React/Next/Angular, Python, Java, SQL, Docker, K8s/OpenShift) | ✅ |
| Ejemplo funcional de gate en CI + guía genérica | ✅ local; ⏳ ejecución en GitHub |
| Paquete local con manifiesto y hashes | ✅ (`tools/build_package.py` → `dist/`) |

## Pendientes concretos (en orden de impacto)

1. ~~Binarios reales~~ **Hecho el 2026-10-01** (ver `VALIDATION.md`). Queda probar versiones mínimas/máximas de cada herramienta y los códigos de salida 127/128 de OSV-Scanner.
2. **Validación dentro de los clientes** — Codex hecho (ver `VALIDATION.md`). Faltan Cursor y Claude Code (sesión iniciada), `--invocation manual` en cada uno, y la resistencia a prompt injection del LLM.
3. **Windows** — ejecutar `install.ps1` y la suite en Windows; correr la matriz `.github/workflows/tests.yml` (Linux/macOS/Windows × Python 3.9/3.12).
4. **Fuentes normativas** — validar mappings ISO/IEC 27001:2022 con el texto de la norma y construir el ruleset SOX/ITGC con fuentes primarias SEC/PCAOB y la política de la organización (hoy `validated: false`).
5. **Python 3.11+** — no probado (la especificación proponía 3.11+; se bajó a 3.9, ver `ARCHITECTURE.md`).
6. Medir calidad de la revisión del agente en código real (falsos positivos/negativos).
7. **Decisión del usuario:** licencia (el usuario indicó el 2026-10-01 que *por ahora no*: el skill no declara `license` ni hay archivo LICENSE), nombre/remoto del repositorio y si se publica.

## Opciones fuera de alcance (no implementadas — no son placeholders)

| Extensión | Estado |
|---|---|
| Hooks de Cursor / Claude Code | ➖ no implementado. Interfaz prevista: comando opt-in que escriba la configuración de hooks del cliente con rollback; verificar esquema/eventos reales antes de implementarlo. Hoy no existe ningún archivo de hooks |
| Conectores GitHub/GitLab/Azure DevOps/Jenkins (`provider_verified`) | ➖ no implementado. Hoy la evidencia importada se limita a `user_supplied` |
| Trivy (contenedores/IaC), SARIF, HTML, PDF, firmas, almacenamiento externo de evidencia | ➖ no implementado. La revisión de infraestructura se cubre con controles locales (Dockerfile) y revisión asistida (K8s/OpenShift) |
| Integración con BYF | ➖ tarea posterior; el core no tiene dependencias de BYF |
| PCI DSS / SOC 2 | ➖ no implementado |
| Baseline contra la rama base (introducido vs preexistente) | ➖ no implementado: `baseline_status` siempre `unknown` |

## Handoff (si se corta la sesión)

- Código del skill: `skills/security-compliance/` (entrada `scripts/sc.py`, módulos en `scripts/sc_core/`). Catálogo: editar `tools/gen_catalog.py` y ejecutarlo (regenera `controls/catalog.json` y `docs/CONTROL-MAPPING.md`; valida IDs ASVS contra `controls/baselines.json`, que sale de `tools/extract_asvs_ids.py`).
- Pruebas: `cd tests && python3 -m unittest discover -s . -v`. Paquete: `python3 tools/build_package.py`.
- Si cambia un fixture de `tests/fixtures/{vuln_app,nest_global_guard}`, hay que rehacer su revisión registrada (`tests/fixtures/reviews/`): el `snapshot_hash` deja de coincidir.
- Nada del skill se instaló en el home del usuario ni se publicó/subió a ningún remoto. No hay commits creados por esta tarea. Con autorización del usuario se instalaron con Homebrew Semgrep, Gitleaks y OSV-Scanner (herramientas del sistema, no parte del paquete).
