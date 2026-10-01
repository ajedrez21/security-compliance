# Fuentes y verificación previa

Consultadas el **2026-09-30**. Las decisiones del producto (comandos `sc.py`, estados, IDs `SEC-/ITGC-/ISO-`, criterios AC) no son normativas oficiales.

| Tema | Fuente | Qué se verificó | Qué NO se verificó |
|---|---|---|---|
| Formato Agent Skills | https://agentskills.io/specification | Campos de frontmatter y restricciones (`name` 1-64 `[a-z0-9-]`, igual al directorio; `description` ≤ 1024; `compatibility` ≤ 500; `metadata` string→string); estructura `scripts/ references/ assets/`; SKILL.md < 500 líneas | Validación con `skills-ref` |
| Cursor | https://cursor.com/docs/skills | Rutas (`.agents/skills`, `.cursor/skills`, compat. `.claude`, `.codex`), campos, `/` para invocar, `disable-model-invocation` | Precedencia de duplicados |
| Claude Code | https://code.claude.com/docs/en/skills | Rutas, precedencia Enterprise > Personal > Proyecto, campos del frontmatter, `/skill-name`, `${CLAUDE_SKILL_DIR}`, `disable-model-invocation` | Comportamiento de argumentos en la versión 2.1.195 |
| Codex | https://developers.openai.com/codex/skills (redirige a https://learn.chatgpt.com/docs/build-skills) | Rutas (`.agents/skills`, `$HOME/.agents/skills`, `/etc/codex/skills`), `agents/openai.yaml` con `policy.allow_implicit_invocation`, invocación `$skill`/`@skill`, no fusiona homónimos | Ruta heredada `~/.codex/skills` (solo vista como compat. desde Cursor) |
| OWASP ASVS | https://github.com/OWASP/ASVS/releases (tag `v5.0.0_release`, 2025-05-30) y datos JSON oficiales `5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json` | 5.0.0 es la última versión estable; 17 capítulos, **345 requisitos**; IDs y niveles usados en el catálogo se verifican programáticamente (`tools/gen_catalog.py`, `tests/test_core.py`) | No se guarda el texto de los requisitos; las relaciones control↔requisito son criterio propio |
| ISO/IEC 27001 | https://www.iso.org/standard/27001 (ficha) | — (la ficha respondió 403 al lector automático) | **Texto de la norma no consultado.** Edición propuesta 2022; los mappings ISO son temáticos y `validated: false`. La numeración Annex A es conocimiento público no validado contra la norma |
| SOX / ITGC | — | — | **Fuentes primarias SEC/PCAOB no incorporadas**; el ruleset es propio y condicionado a la política de la organización (`validated: false`) |
| Semgrep | https://docs.semgrep.dev/cli-reference | Reglas locales (`--config` archivo) funcionan sin red; los registros requieren red; `--metrics=off`; salida `--json` | Flags exactos por versión se detectan en ejecución (`--help`); reglas locales validadas con `semgrep --validate` (1.176.0) y ejecutadas con el binario real (2026-10-01) |
| Gitleaks | https://github.com/gitleaks/gitleaks | MIT; subcomandos `git`/`dir`/`stdin` (≥ 8.19; `detect/protect` ocultos); `--report-format json`, `--report-path`, `--redact`, `--exit-code`, `--no-banner`, `--config`; exit 0/1/126; proyecto en mantenimiento (solo parches) | — (`--gitleaks-ignore-path` y la ejecución real verificados con 8.30.1) |
| OSV-Scanner | https://github.com/google/osv-scanner (README) | Sintaxis v2 `osv-scanner scan source -r <dir>`; `--format json`; modo offline con `--download-offline-databases` | Códigos 127/128 (de la documentación del proyecto, no reproducidos); la estructura JSON y los códigos 0/1 se verificaron con el binario real 2.6.0 |

## Decisiones derivadas

- Reglas Semgrep del registro **no** se usan (reproducibilidad y red). Conjunto local mínimo propio.
- OSV-Scanner consulta `api.osv.dev` con ecosistema/nombre/versión de paquetes: solo si `network.allow_external_scanners: true`.
- ISO y SOX quedan **pendientes de validación de fuentes**; no se presentan como referencia oficial exacta.
