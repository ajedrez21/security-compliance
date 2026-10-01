# Arquitectura

```text
Cliente (Cursor / Claude Code / Codex)
  └─ lee SKILL.md ─► el agente razona (autorización, flujo, arquitectura) ─► review.json
                         │ ejecuta
                         ▼
               scripts/sc.py (runner, sin LLM, solo stdlib)
   config ─ inventory/git ─ adapters (Semgrep, Gitleaks, OSV) ─ evidence/review import
                         │                                              │
                         └──────────► evaluate (controles) ─► gate ─► report.json / report.md
```

## Responsabilidades

| Componente | Responsabilidad |
|---|---|
| `SKILL.md` + `references/` | Activación, selección de comando, alcance, flujo, límites; lectura selectiva |
| Agente del cliente | Interpretación del código y la arquitectura; hallazgos fundamentados |
| Runner (`sc_core/`) | Inventario, ejecución controlada de herramientas, validación, reportes y gate |
| `controls/catalog.json` | 50 controles con IDs propios, aplicabilidad, evidencia, método, limitaciones, mappings con fuente/versión |
| Adaptadores | Diferencias entre scanners (`tools/`) y clientes (`installer/`, `clients.py`) |

## Módulos del runner

`miniyaml` (YAML seguro de subconjunto) · `schema` (validador JSON Schema de subconjunto; rechaza palabras clave no soportadas) · `config` (precedencia, política confiable, hash) · `gitutil` (solo lectura, sin shell, sin hooks) · `inventory` (alcance, snapshot, stacks, dependencias) · `tools/*` · `localchecks` (heurísticas y comprobaciones locales) · `evidence` · `evaluate` (controles y gate) · `report` (JSON/Markdown, saneamiento) · `commands` (orquestación) · `doctor`, `init_cmd`, `skillcheck`, `clients`.

## Decisiones

- **Python ≥ 3.9, solo biblioteca estándar.** La especificación proponía 3.11+; se bajó el mínimo a 3.9 porque es lo que trae macOS con las Command Line Tools y para evitar un runtime/venv por dependencias. Sin PyYAML/jsonschema: un parser YAML seguro y un validador de schemas de subconjunto, ambos con rechazo explícito de lo no soportado. *(Probado en 3.9.6; 3.11+ no ejecutado en este entorno.)*
- **Métodos de control:** `scanner` (Semgrep/Gitleaks/OSV), `local` (lockfiles, Dockerfile), `agent` (revisión importada), `evidence` (PR/CI/proceso importados), `derived` (ISO resume SEC).
- **Heurísticas** (regex) producen candidatos con origen `heuristic`; nunca bloquean el gate ni reemplazan a un scanner.
- **Un scanner faltante = `NOT_RUN`** (no `PASS`); timeout/JSON inválido/error = `ERROR`; sin paquetes analizados = `UNKNOWN`.
- **Semgrep con reglas locales versionadas** (`rulesets/semgrep-local.yml`): reproducible y sin red; no se usan reglas del repositorio ni del registro. Gitleaks con configuración propia (`extend useDefault` + allowlist de `paths.exclude`). OSV solo con `network.allow_external_scanners: true`.
- **Instalación por copia** (sin symlinks), marcador `.sc-install.json` con hashes para idempotencia, detección de cambios locales y desinstalación segura.
- **Procedencia** (`local_observation`, `scanner`, `agent_review`, `user_supplied`, `provider_verified`, y `heuristic` solo para hallazgos): cada una solo puede resolver los controles de su método (ver `skills/security-compliance/references/evidence-policy.md`). Sin conectores, el máximo para evidencia importada es `user_supplied`.

## Seguridad del propio flujo

Sin shell en subprocess; PATH explícito (`SC_*_BIN`) y nunca binarios del proyecto; entorno mínimo para herramientas; reportes saneados (redacción de credenciales, escape de Markdown, `final_scrub`); Gitleaks nunca persiste `Secret`/`Match`; supresiones inline (`gitleaks:allow`, `nosemgrep`) se advierten; texto dirigido a agentes en el repositorio se trata como dato y se advierte.
