# Validación

Este documento registra qué se validó, **con qué nivel de realismo** y qué quedó pendiente. No se simulan resultados escritos a mano: todo lo marcado como ejecutado se ejecutó en la máquina de desarrollo y se reproduce con:

```bash
cd tests && python3 -m unittest discover -s . -v
```

## Entorno de la validación

| Elemento | Valor |
|---|---|
| Fecha | 2026-09-30 / 2026-10-01 (UTC) |
| Sistema | macOS 26.5.1 (Darwin 25.5.0, arm64) |
| Python | 3.9.6 (Command Line Tools). **3.11+ no disponible en la máquina: no ejecutado** |
| git | 2.50.1 |
| Scanners reales | Instalados con Homebrew el 2026-10-01 (autorizado por el usuario): Semgrep 1.176.0, Gitleaks 8.30.1, OSV-Scanner 2.6.0 |
| Clientes instalados | Cursor 3.16.17, Claude Code 2.1.195 (CLI sin sesión iniciada), codex-cli 0.142.3 |
| Resultado de la suite | **166 pruebas: 165 OK, 1 omitida** (comprobación cruzada opcional con `jsonschema`, no instalado), 0 fallos; con `SC_TEST_NETWORK=1`. Sin esa variable la prueba de OSV real también se omite |

## Niveles de evidencia

| Nivel | Significado |
|---|---|
| **Fixture + código real** | Proyecto sintético y ejecución del código real del skill/instalador (sin herramientas externas) |
| **Simulado (fake)** | Adaptador ejercitado con un ejecutable falso que emite salida enlatada. Prueba la lógica de adaptación, **no** al scanner real |
| **Binario real** | Ejecutado con Semgrep/Gitleaks/OSV-Scanner reales (`tests/test_real_binaries.py`) |
| **Dentro del cliente** | Comprobado dentro de Cursor/Claude Code/Codex — **ninguno realizado** |
| **Pendiente** | No ejecutado |

## Criterios de aceptación

| ID | Criterio (resumido) | Nivel | Prueba / evidencia | Pendiente |
|---|---|---|---|---|
| AC-01 | Un core portable, sin BYF ni API keys LLM | Fixture + código real | `test_cli.TestIndependence` (búsqueda en `skills/` e `installer/`; solo stdlib; un único skill) | — |
| AC-02 | Frontmatter válido y referencias internas resuelven tras instalar | Fixture + código real | `skillcheck.validate_package` en `test_installer.TestInstallPaths` (copia instalada de los 3 clientes × 2 alcances); `doctor` | Validación con `skills-ref` (no instalado) |
| AC-03 | `help` y `doctor` en proyecto vacío y sin scanners | Fixture + código real | `test_cli.TestHelpDoctorInit` | — |
| AC-04 | Instalación global/proyecto con rutas temporales, espacios y Unicode; sin admin | Fixture + código real (macOS) | `test_installer.TestInstallPaths`, `test_journey` | **Windows: no ejecutado** (`install.ps1` revisado, no corrido); Linux: no ejecutado |
| AC-05 | Reinstalación idempotente; actualización fallida con rollback; cambios ajenos preservados | Fixture + código real | `test_installer.TestIdempotenceUpdateRollback` (fallo inyectado tras el respaldo → restaura) | — |
| AC-06 | Desinstalar no borra otros skills ni configuración compartida | Fixture + código real | `TestUninstallAndNonInterference` | — |
| AC-07 | Auditoría sin YAML; `init` crea configuración válida y no pisa una existente | Fixture + código real | `test_cli.TestHelpDoctorInit` | — |
| AC-08 | YAML inválido, campos peligrosos y rutas fuera de alcance → error claro | Fixture + código real | `test_core.TestMiniYaml`, `TestConfig` (9 casos) | — |
| AC-09 | Monorepos/mixtos sin inventar stacks | Fixture + código real | `test_core.TestInventoryAndStacks` | — |
| AC-10 | Adaptadores distinguen limpio, hallazgos, timeout, binario ausente, JSON inválido y error | **Simulado (fake)** para los 6 estados; **Binario real** para limpio y hallazgos | `test_adapters.TestAdapterStates`; `test_real_binaries` (3 herramientas) | timeout/JSON inválido/error con binario real: no reproducibles a propósito |
| AC-11 | Herramienta faltante o scanner sin cobertura ≠ PASS | Fixture + código real (binarios realmente ausentes) y fake | `TestScannerCoverageInReports` | — |
| AC-12 | Secreto sintético: resultado pertinente y nunca persistido | Fake + heurística + **Gitleaks real** | `TestScannerCoverageInReports`; `test_real_binaries.TestRealGitleaks` (PAT sintético; busca el valor en reportes, tool-output, stdout/stderr) | — |
| AC-13 | Autorización global no se marca vulnerable por falta de decorador local | Fixture + código real + revisión de agente registrada | `test_recorded_reviews`, `TestAgentReview.test_runner_never_flags…` | Calidad del LLM en otros stacks: no medida |
| AC-14 | Evidencia ausente → UNKNOWN; workflow ≠ ejecución exitosa | Fixture + código real | `test_evidence_review.TestItgcEvidence` | — |
| AC-15 | Evidencia de otro repo/SHA o anterior al cambio → rechazada/no concluyente | Fixture + código real | `TestEvidenceValidation` | — |
| AC-16 | Reportes distinguen aportada, agente y proveedor | Fixture + código real | `provider_verified` degradado a `user_supplied` + `provenance_declared`; `agent_review` | Conectores `provider_verified`: no implementados |
| AC-17 | `diff`: staged, unstaged, untracked, renombres, repo sin commits | Fixture + código real (git real) | `test_git_scope.TestChangedFiles` | — |
| AC-18 | Base inexistente, shallow clone y cambios durante la revisión | Fixture + código real (+ fake que muta archivos) | `TestBaseErrors`, `TestConcurrentChange` | Shallow con base existente pero sin merge-base: no probado |
| AC-19 | JSON valida schema; Markdown y JSON coinciden | Fixture + código real | `test_cli.TestReports` | — |
| AC-20 | Gate y exit codes para todos los estados y precedencia; alcance vacío no pasa | Fixture + código real | `test_gate` (23+ pruebas) | — |
| AC-21 | Sin afirmaciones de certificación ni de nivel ASVS | Fixture + código real | `test_cli.TestReports.test_no_certification_claims`, `test_docs` | — |
| AC-22 | Mappings con fuente y versión; no validado ≠ oficial | Fixture + código real | `test_core.TestCatalog`; IDs ASVS verificados contra los datos oficiales | **ISO/IEC 27001 y SOX/SEC/PCAOB: fuentes no validadas** (documentado) |
| AC-23 | README malicioso no cambia políticas, comandos ni conclusión | Fixture + código real (runner) | `test_evidence_review.TestPromptInjection` | **Resistencia del LLM dentro de cada cliente: pendiente** |
| AC-24 | La instalación no habilita hooks ni reglas obligatorias | Fixture + código real | `TestUninstallAndNonInterference.test_install_does_not_enable_hooks…` | — |
| AC-25 | CI bloquea según política, conserva reportes saneados; el PR no rebaja la política | Fixture + código real (+ fake gitleaks) | `test_gate.TestCiPolicy`, `TestCiGateScript` | **Workflow de GitHub Actions no ejecutado**; protección de rama no configurada |
| AC-26 | Proyectos básicos Node y .NET/Python producen reportes completos | Fixture + código real | `test_cli.TestStacksEndToEnd` (Node, Python y .NET) | Sin scanners reales los controles de scanner quedan `NOT_RUN` |
| AC-27 | Paquete distribuible funciona desde otra ubicación | Fixture + código real | `test_installer.TestWrapperAndPackage` (zip determinístico, hashes, instalación desde el zip extraído) | — |
| AC-28 | Guías de los tres clientes con instalación, descubrimiento, uso manual, actualización y desinstalación | Fixture + código real | `test_docs` | Contenido no comprobado dentro de los clientes |
| AC-29 | Documentación distingue pruebas reales, fixtures y validación pendiente | — | Este documento + `test_docs` | — |
| AC-30 | Todos los comandos existen, están documentados y se comportan | Fixture + código real | `test_cli.TestAllCommands` | — |

Recorrido completo (instalar → doctor → init → diff/audit → reporte → actualizar → desinstalar): `test_journey`, ejecutando todo **desde la copia instalada**.

## Revisión asistida: casos positivos y negativos (registro de razonamiento)

`tests/fixtures/vuln_app` y `tests/fixtures/nest_global_guard` fueron revisados por Claude Code (claude-sonnet-5-5) siguiendo el `review_procedure` del catálogo; las revisiones se guardan en `tests/fixtures/reviews/` y `test_recorded_reviews` comprueba que el pipeline las importa y produce los estados esperados.

| Fixture | Control | Resultado | Razonamiento / evidencia observada |
|---|---|---|---|
| vuln_app | SEC-AUTHZ-001 | **FAIL** (positivo) | `GET /api/export/all-customers` (`server.js:29`) no pasa por ningún middleware y no hay `app.use(requireAuth)` global; las demás rutas sí lo usan → omisión puntual, no política global |
| vuln_app | SEC-INPUT-001 | **FAIL** (positivo) | `server.js:17` concatena `req.query.name`; las consultas de `/api/orders` y el `DELETE` usan `$1` (no se reportan) |
| vuln_app | SEC-INPUT-003 | **FAIL** (positivo) | `server.js:36` `eval(req.body.expression)` |
| vuln_app | SEC-INPUT-002 | **PASS** (negativo: patrón presente, no es hallazgo) | `view.js` usa `innerHTML` solo con una constante y `textContent` para el dato dinámico |
| vuln_app | SEC-AUTHN-001 | **PASS** | `auth.js:7` `jwt.verify` con `algorithms: ['RS256']`, issuer y audience |
| vuln_app | SEC-AUTHZ-002 | **UNKNOWN** (negativo: no concluir) | Sin modelo de propiedad de `customers` visible |
| nest_global_guard | SEC-AUTHZ-001 | **PASS** (AC-13) | Controlador sin decoradores locales pero `APP_GUARD` global default-deny; solo `@Public()` lo omite |
| nest_global_guard | SEC-AUTHZ-002 | **PASS** | El guard exige `user.sub === req.params.id` o admin para rutas con `:id` |
| nest_global_guard | SEC-AUTHN-001 | **UNKNOWN** | La estrategia JWT que puebla `req.user` no está en el código revisado |

**Sesgo y alcance de esta validación:** el mismo agente escribió los fixtures y los revisó (los casos son claros por construcción), y son 2 proyectos pequeños. Demuestra que el flujo de revisión → importación → reporte funciona y que los procedimientos son seguibles; **no mide la tasa de falsos positivos/negativos de un LLM** sobre código real, que depende del cliente y del modelo. Esa medición queda pendiente.

## Validación dentro de clientes

| Cliente | Intento | Resultado |
|---|---|---|
| Claude Code 2.1.195 | Instalación por proyecto en un directorio temporal (`.claude/skills/security-compliance`) y `claude -p "/security-compliance help"` | **No concluyente**: el CLI respondió `Not logged in · Please run /login`; no se pudo comprobar el descubrimiento. No se inició sesión en nombre del usuario |
| Cursor 3.16.17 | No intentado (requiere abrir la app y el chat del Agent) | **Pendiente** |
| codex-cli 0.142.3 (modelo gpt-5.5) | 2026-10-01, con autorización del usuario y tras `codex login`: instalación por proyecto en un repo temporal (`.agents/skills/security-compliance`) | **Validado.** (1) `$security-compliance help` → Codex descubrió el skill, ejecutó `sc.py help` y mostró la ayuda sin iniciar ninguna auditoría. (2) `$security-compliance diff` sobre un archivo con `eval(process.argv[2])` → Codex ejecutó el runner (run `…014334ec9`, gate `INCOMPLETE`, revisión `NOT_RUN`), analizó el control `SEC-INPUT-003` por su cuenta, escribió `review.json` y lo reimportó (run `…b65cec0e`): revisión **aceptada**, hallazgo `high` en `b.js:1` con flujo, `SEC-INPUT-003` = `FAIL`, gate `BLOCKED` (modo advisory, salida 0). Su resumen declaró los límites (OSV no ejecutado por política, 24 controles sin concluir). Observación: dentro del sandbox `workspace-write` de Codex, Semgrep falló con `ca-certs: empty trust anchors` y el runner lo reportó como `ERROR` (no `PASS`), como corresponde; Gitleaks (sin red) sí corrió. |

Procedimiento de validación manual por cliente: ver `integrations/<cliente>/README.md` («Verificar el descubrimiento»).

## Validación con binarios reales (2026-10-01)

`tests/test_real_binaries.py` (se omite si falta la herramienta; OSV requiere `SC_TEST_NETWORK=1` porque envía nombre/versión de paquetes **sintéticos** a api.osv.dev) y una corrida end-to-end sobre un proyecto sintético:

| Herramienta | Verificado con el binario real |
|---|---|
| Semgrep 1.176.0 | `--validate` de las 13 reglas locales: válidas; flag `--x-ignore-semgrepignore-files` presente; hallazgos normalizados; alcance por archivos cambiados; proyecto limpio |
| Gitleaks 8.30.1 | Subcomando `dir`, `--exit-code 2`, `--redact`, `--gitleaks-ignore-path` (un `.gitleaksignore` del repo **no** suprime hallazgos); el secreto sintético no aparece en ningún artefacto, stdout ni stderr |
| OSV-Scanner 2.6.0 | `scan source -r --format json --config`; JSON de `lodash@4.17.15` interpretado (3 high + 3 medium), solo con `network.allow_external_scanners: true` |

**Defectos que solo apareció con binarios reales (corregidos):**
1. Semgrep antepone la ruta de la config al `rule_id`; ahora se normaliza a `sc.…`.
2. Gitleaks detectó el secreto sintético solo como `generic-api-key` (confianza baja) y el control quedó en `PASS`. Un scanner que reporta algo, aunque sea de baja confianza, ahora deja el control en `UNKNOWN` (nunca `PASS`).

## Limitaciones conocidas de la validación

- Timeout, JSON inválido y error técnico con binarios reales no se reproducen a propósito (solo con fakes).
- Los códigos de salida de OSV-Scanner 128 (sin paquetes) y 127 no se reprodujeron con el binario real.
- Windows/PowerShell y Linux sin ejecutar; hay una matriz de CI preparada (`.github/workflows/tests.yml`) **no ejecutada**.
- Python 3.11+ no probado.
- Las reglas Semgrep son un conjunto mínimo propio (13 reglas): detectan patrones, no sustituyen a un SAST completo.
