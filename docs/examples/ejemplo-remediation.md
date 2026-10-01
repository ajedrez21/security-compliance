# Plan de remediación — vuln\_app

> Revisión de controles técnicos basada en la evidencia disponible. No constituye una certificación ni una afirmación de cumplimiento SOX, ISO/IEC 27001 u OWASP ASVS: la ausencia de evidencia no equivale a aprobación, y los controles marcados UNKNOWN/NOT\_RUN/ERROR no fueron verificados.

- **Run:** `20261001T023459Z-4f6ae0fa` · **Comando:** `security` · **Fecha (UTC):** 2026-10-01T02:34:59Z
- **Resultado del gate:** `BLOCKED` · **Snapshot:** `sha256:92d9e4aa5dbf1c84`…
- **Problemas a corregir:** 3 (Crítica: 1, Alta: 1, Media: 1)

## Cómo se priorizó

Se ordena por severidad (impacto y exposición), luego por confianza. Marcá cada casilla al corregir y repetí la revisión para confirmar.

| Severidad | Criterio | Prioridad sugerida |
|---|---|---|
| Crítica | Explotable con impacto severo (ejecución de código, exposición masiva de datos, toma de control) y poco o ningún requisito previo. | Inmediata: corregir antes de seguir desplegando. |
| Alta | Vulnerabilidad probable con impacto grave, o explotable por usuarios autenticados. | Corta: planificar en el sprint actual. |
| Media | Debilidad con impacto acotado o que requiere condiciones adicionales para explotarse. | Media: planificar en el próximo ciclo. |
| Baja | Mala práctica o riesgo menor sin explotación directa evidente. | Baja: corregir cuando se toque el código. |
| Informativa | Observación sin riesgo directo; mejora o contexto. | Opcional. |

_Las prioridades son una sugerencia del skill; la política de plazos la define la organización._

## Progreso desde la revisión anterior

Comparado con `20261001T023457Z-f870262f` (2026-10-01T02:34:57Z): gate `INCOMPLETE` → `BLOCKED`.

- Problemas: **5 → 3** · resueltos **1** · persisten **3** · nuevos **0** · sin reverificar **1**

### ✅ Resueltos (el control se reverificó y el hallazgo ya no aparece)

- [x] Crítica · eval() sobre una expresión recibida del cliente — `src/server.js:36` (`SEC-INPUT-003`)

### ❓ Sin reverificar (no se puede afirmar que se corrigieron)

Su control no se pudo evaluar en esta ejecución (por ejemplo: el código cambió y falta repetir la revisión del agente, o falta un scanner).

- [ ] Media · Uso de eval; permite ejecución de código si recibe datos externos. — `src/server.js:36` (`SEC-SAST-001`) — control ahora: UNKNOWN

### Controles que cambiaron de estado

- `SEC-INPUT-003`: NOT_RUN → PASS

## Problemas a corregir

### Crítica (1)

- [ ] **1. Exportación de todos los clientes sin autenticación ni autorización** — `src/server.js:29` (**bloquea el gate**)
  - **Qué pasa:** La ruta GET /api/export/all-customers devuelve id, name, email y tax\_id de todos los clientes sin ningún control de acceso. Flujo: GET /api/export/all-customers (sin credenciales) → handler anónimo → db.query SELECT sobre customers → respuesta JSON completa. No hay middleware global (app.use) ni guard por ruta; las demás rutas sí usan requireAuth, lo que confirma que es una omisión puntual y no una política global.
  - **Riesgo:** Exposición masiva de datos personales (email, identificador fiscal) a cualquier visitante.
  - **Qué hacer:** Agregar requireAuth y requireRole('admin') o una política equivalente; evaluar si la exportación debe existir y registrarla como evento auditable.
  - **Normas:** OWASP ASVS 5.0.0 V8.1.1 (exacta); OWASP ASVS 5.0.0 V8.2.1 (exacta); OWASP ASVS 5.0.0 V8.3.1 (exacta)
  - **Control:** `SEC-AUTHZ-001` · **Origen:** revisión del agente · **ID:** `F-d7e42cab6072`

### Alta (1)

- [ ] **2. Concatenación de req.query.name en una sentencia SQL** — `src/server.js:17` (**bloquea el gate**)
  - **Qué pasa:** El parámetro name se concatena dentro de comillas simples en el SQL ejecutado por db.query sin parametrizar ni validar. Flujo: GET /api/customers?name=… (usuario autenticado) → req.query.name → concatenación en 'sql' → db.query(sql). Control existente: solo autenticación; no hay validación ni parámetros.
  - **Riesgo:** Inyección SQL: lectura o modificación de datos con los privilegios de la cuenta de la aplicación.
  - **Qué hacer:** Usar db.query('SELECT id, name FROM customers WHERE name = $1', \[req.query.name\]).
  - **Normas:** OWASP ASVS 5.0.0 V1.2.4 (exacta)
  - **Control:** `SEC-INPUT-001` · **Origen:** revisión del agente · **ID:** `F-66c38b045536`

### Media (1)

- [ ] **3. Asignación a innerHTML; riesgo de XSS si el valor no está saneado.** — `src/view.js:3` (confianza baja)
  - **Qué pasa:** Asignación a innerHTML; riesgo de XSS si el valor no está saneado.
  - **Riesgo:** Patrón de código asociado a una vulnerabilidad; requiere validar el flujo de datos.
  - **Qué hacer:** Revisar el hallazgo, corregir el patrón inseguro o documentar una excepción justificada.
  - **Normas:** OWASP ASVS 5.0.0 V15.3.5 (temática); ISO/IEC 27001:2022 (Annex A) Annex A A.8.29 (temática, no validada)
  - **Control:** `SEC-SAST-001` · **Origen:** scanner · **ID:** `F-259a7c650526`

## Pendiente de verificar (no son defectos confirmados)

Estos controles no se pudieron comprobar. Hasta resolverlos, no hay garantía sobre ellos.

- [ ] `SEC-AUTHN-001` Validación de tokens y emisor/audiencia — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-AUTHN-002` Sesiones y cookies seguras — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-AUTHN-003` Autenticación: fuerza bruta y cuentas por defecto — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-AUTHZ-002` Acceso por objeto y aislamiento entre tenants — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-INPUT-002` Codificación de salida y XSS — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-INPUT-004` Validación de entrada en capa de servicio de confianza — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-API-001` CORS y CSRF — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-API-002` SSRF y llamadas a recursos externos — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-API-003` Límites de consumo y anti-automatización — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-API-004` Exposición excesiva de datos y mass assignment — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-FILE-001` Subida de archivos: tamaño, tipo y almacenamiento — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-FILE-002` Nombres de archivo y path traversal — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-CRYPTO-001` Algoritmos criptográficos, hashing y aleatoriedad — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-CRYPTO-002` TLS y validación de certificados — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-DATA-001` Datos sensibles y minimización — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-LOG-001` Eventos de seguridad auditables — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-LOG-002` Manejo de errores y modo debug — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-WEB-001` Cabeceras de seguridad del navegador — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-DB-001` Base de datos: roles mínimos y migraciones destructivas — No ejecutado: La revisión importada no cubre este control.
- [ ] `SEC-SAST-001` Análisis estático (SAST) sin hallazgos bloqueantes — Desconocido: semgrep reportó 1 hallazgo(s) de baja confianza pendientes de triage; no se puede afirmar PASS.
- [ ] `SEC-DEPS-001` Dependencias sin vulnerabilidades conocidas — No ejecutado: osv-scanner: No se ejecutó: network.allow\_external\_scanners=false. La consulta enviaría a api.osv.dev ecosistema, nombre y versión de cada paquete (no el código). Habilítelo explícitamente o use una base offline fuera de este skill.
- [ ] `SEC-INFRA-004` Separación de ambientes y configuración — No ejecutado: La revisión importada no cubre este control.

## Próximos pasos para completar la revisión

1. 20 control(es) de revisión del agente sin verificar: pedir al agente que los revise y reimportar con --review.
1. Scanners faltantes, con error o sin permiso de red: ver la sección de scanners (se instalan por fuera del skill).

## Limitaciones

- El runner no razona sobre autorización ni arquitectura: los controles de método 'agent' solo se resuelven con una revisión estructurada importada (procedencia agent\_review, no verificada de forma independiente).
- Un archivo de workflow o una rama local no prueban ejecución ni protección remota; sin conector autenticado la evidencia aportada no se verifica de forma independiente.
- El skill no ejecuta build, tests ni código del proyecto auditado (se trata como código no confiable).
