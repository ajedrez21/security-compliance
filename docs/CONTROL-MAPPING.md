# Mapeo de controles

Generado por `tools/gen_catalog.py` desde `skills/security-compliance/controls/catalog.json`. No editar a mano.

- **exact (validada)**: el ID existe en la baseline oficial indicada (verificado contra los datos publicados) y expresa el tema del control.
- **thematic**: relación temática; no implica equivalencia. Los mappings ISO/IEC 27001:2022 y SOX/ITGC están **pendientes de validación** (ver `docs/SOURCES.md`).
- Los IDs `SEC-*`, `ITGC-*`, `ISO-*` son identificadores propios de este producto, no numeración oficial.

## Seguridad de aplicación

| ID | Control | Método | Mappings |
|---|---|---|---|
| `SEC-AUTHN-001` | Validación de tokens y emisor/audiencia | agent | owasp_asvs V9.1.1 (exacta); owasp_asvs V9.1.2 (exacta); owasp_asvs V9.1.3 (exacta); owasp_asvs V9.2.1 (exacta); owasp_asvs V9.2.3 (exacta) |
| `SEC-AUTHN-002` | Sesiones y cookies seguras | agent | owasp_asvs V7.2.1 (exacta); owasp_asvs V7.2.2 (exacta); owasp_asvs V7.2.4 (exacta); owasp_asvs V7.4.1 (exacta); owasp_asvs V3.3.1 (exacta); owasp_asvs V3.3.2 (exacta); owasp_asvs V3.3.4 (exacta) |
| `SEC-AUTHN-003` | Autenticación: fuerza bruta y cuentas por defecto | agent | owasp_asvs V6.3.1 (exacta); owasp_asvs V6.3.2 (exacta); owasp_asvs V6.4.1 (exacta) |
| `SEC-AUTHZ-001` | Autorización a nivel de función y de servicio | agent | owasp_asvs V8.1.1 (exacta); owasp_asvs V8.2.1 (exacta); owasp_asvs V8.3.1 (exacta) |
| `SEC-AUTHZ-002` | Acceso por objeto y aislamiento entre tenants | agent | owasp_asvs V8.2.2 (exacta); owasp_asvs V8.2.3 (exacta); owasp_asvs V8.4.1 (exacta) |
| `SEC-INPUT-001` | Consultas parametrizadas (inyección SQL/NoSQL) | agent | owasp_asvs V1.2.4 (exacta) |
| `SEC-INPUT-002` | Codificación de salida y XSS | agent | owasp_asvs V1.1.2 (exacta); owasp_asvs V1.2.1 (exacta); owasp_asvs V1.3.1 (exacta); owasp_asvs V3.2.2 (exacta) |
| `SEC-INPUT-003` | Inyección de comandos, código dinámico y deserialización | agent | owasp_asvs V1.2.5 (exacta); owasp_asvs V1.3.2 (exacta); owasp_asvs V1.5.1 (exacta); owasp_asvs V1.5.2 (exacta) |
| `SEC-INPUT-004` | Validación de entrada en capa de servicio de confianza | agent | owasp_asvs V2.2.1 (exacta); owasp_asvs V2.2.2 (exacta); owasp_asvs V2.3.1 (exacta) |
| `SEC-API-001` | CORS y CSRF | agent | owasp_asvs V3.4.2 (exacta); owasp_asvs V3.5.1 (exacta); owasp_asvs V3.5.2 (exacta); owasp_asvs V3.5.3 (exacta) |
| `SEC-API-002` | SSRF y llamadas a recursos externos | agent | owasp_asvs V1.3.6 (exacta); owasp_asvs V13.2.4 (exacta); owasp_asvs V15.3.2 (exacta) |
| `SEC-API-003` | Límites de consumo y anti-automatización | agent | owasp_asvs V2.4.1 (exacta); owasp_asvs V15.2.2 (exacta) |
| `SEC-API-004` | Exposición excesiva de datos y mass assignment | agent | owasp_asvs V15.3.1 (exacta); owasp_asvs V15.3.3 (exacta); owasp_asvs V14.2.6 (exacta) |
| `SEC-FILE-001` | Subida de archivos: tamaño, tipo y almacenamiento | agent | owasp_asvs V5.2.1 (exacta); owasp_asvs V5.2.2 (exacta); owasp_asvs V5.3.1 (exacta) |
| `SEC-FILE-002` | Nombres de archivo y path traversal | agent | owasp_asvs V5.3.2 (exacta); owasp_asvs V5.4.1 (exacta); owasp_asvs V5.4.2 (exacta) |
| `SEC-SECRETS-001` | Sin secretos embebidos en el alcance | scanner | owasp_asvs V13.3.1 (temática); iso27001 Annex A A.8.24 (temática, no validada) |
| `SEC-CRYPTO-001` | Algoritmos criptográficos, hashing y aleatoriedad | agent | owasp_asvs V11.3.1 (exacta); owasp_asvs V11.3.2 (exacta); owasp_asvs V11.4.1 (exacta); owasp_asvs V11.4.2 (exacta); owasp_asvs V11.5.1 (exacta) |
| `SEC-CRYPTO-002` | TLS y validación de certificados | agent | owasp_asvs V12.1.1 (exacta); owasp_asvs V12.2.1 (exacta); owasp_asvs V12.3.2 (exacta) |
| `SEC-DATA-001` | Datos sensibles y minimización | agent | owasp_asvs V14.2.1 (exacta); owasp_asvs V14.2.2 (exacta); owasp_asvs V16.2.5 (exacta) |
| `SEC-LOG-001` | Eventos de seguridad auditables | agent | owasp_asvs V16.3.1 (exacta); owasp_asvs V16.3.2 (exacta); owasp_asvs V16.3.3 (exacta) |
| `SEC-LOG-002` | Manejo de errores y modo debug | agent | owasp_asvs V16.5.1 (exacta); owasp_asvs V16.5.3 (exacta); owasp_asvs V13.4.2 (exacta) |
| `SEC-WEB-001` | Cabeceras de seguridad del navegador | agent | owasp_asvs V3.4.1 (exacta); owasp_asvs V3.4.3 (exacta); owasp_asvs V3.4.4 (exacta); owasp_asvs V3.4.5 (exacta) |
| `SEC-DB-001` | Base de datos: roles mínimos y migraciones destructivas | agent | owasp_asvs V13.3.2 (temática); iso27001 Annex A A.8.3 (temática, no validada) |
| `SEC-SAST-001` | Análisis estático (SAST) sin hallazgos bloqueantes | scanner | owasp_asvs V15.3.5 (temática); iso27001 Annex A A.8.29 (temática, no validada) |
| `SEC-DEPS-001` | Dependencias sin vulnerabilidades conocidas | scanner | owasp_asvs V15.2.1 (temática); iso27001 Annex A A.8.8 (temática, no validada) |
| `SEC-DEPS-002` | Lockfiles presentes para los manifiestos | local | owasp_asvs V15.1.2 (temática) |
| `SEC-INFRA-001` | Contenedores sin ejecución como root | local | owasp_asvs V13.2.6 (temática); iso27001 Annex A A.8.9 (temática, no validada) |
| `SEC-INFRA-002` | Imágenes base fijadas | local | owasp_asvs V15.2.4 (temática); iso27001 Annex A A.8.9 (temática, no validada) |
| `SEC-INFRA-003` | Kubernetes/OpenShift: contexto de seguridad y secretos | agent | owasp_asvs V13.2.6 (temática); iso27001 Annex A A.8.9 (temática, no validada) |
| `SEC-INFRA-004` | Separación de ambientes y configuración | agent | owasp_asvs V13.4.1 (temática); iso27001 Annex A A.8.31 (temática, no validada) |

## SOX / ITGC (ruleset propio)

| ID | Control | Método | Mappings |
|---|---|---|---|
| `ITGC-CHG-001` | Trazabilidad ticket → cambio → PR | evidence | sox_itgc Gestión de cambios: trazabilidad (temática, no validada) |
| `ITGC-CHG-002` | Aprobación independiente vigente sobre el cambio efectivo | evidence | sox_itgc Gestión de cambios: aprobación independiente (temática, no validada) |
| `ITGC-CHG-003` | Resultados de pruebas vinculados al commit exacto | evidence | sox_itgc Gestión de cambios: pruebas (temática, no validada) |
| `ITGC-CHG-004` | Protección de ramas sin bypass | evidence | sox_itgc Gestión de cambios: protección de ramas y de su política (temática, no validada) |
| `ITGC-CHG-005` | Despliegue trazable al artefacto y al commit | evidence | sox_itgc Gestión de cambios: despliegue (temática, no validada) |
| `ITGC-CHG-006` | Revisión de cambios a base de datos y lógica financiera | agent | sox_itgc Gestión de cambios: cambios de datos y lógica crítica (temática, no validada) |
| `ITGC-CHG-007` | Cambios de emergencia con evidencia posterior | evidence | sox_itgc Gestión de cambios: cambios de emergencia (temática, no validada) |
| `ITGC-ACC-001` | Separación de funciones y revisión de accesos | evidence | sox_itgc Acceso y segregación de funciones (temática, no validada) |
| `ITGC-OPS-001` | Backups y restauración | evidence | sox_itgc Operaciones: backups (temática, no validada) |
| `ITGC-OPS-002` | Tareas programadas y atención de fallos | evidence | sox_itgc Operaciones: procesamiento programado (temática, no validada) |

## ISO/IEC 27001 (controles técnicos y evidencia organizacional)

| ID | Control | Método | Mappings |
|---|---|---|---|
| `ISO-TECH-001` | Control de acceso y autenticación en la aplicación | derived | iso27001 Annex A A.8.5 / A.5.15 (temática, no validada) |
| `ISO-TECH-002` | Gestión de vulnerabilidades técnicas | derived | iso27001 Annex A A.8.8 (temática, no validada) |
| `ISO-TECH-003` | Configuración segura de infraestructura | derived | iso27001 Annex A A.8.9 (temática, no validada) |
| `ISO-TECH-004` | Registro, errores y datos sensibles | derived | iso27001 Annex A A.8.15 (temática, no validada) |
| `ISO-TECH-005` | Criptografía y gestión de secretos | derived | iso27001 Annex A A.8.24 (temática, no validada) |
| `ISO-TECH-006` | Codificación segura | derived | iso27001 Annex A A.8.28 (temática, no validada) |
| `ISO-TECH-007` | Pruebas de seguridad ejecutadas sobre el commit | evidence | iso27001 Annex A A.8.29 (temática, no validada) |
| `ISO-TECH-008` | Gestión de cambios técnica (revisión y pruebas) | evidence | iso27001 Annex A A.8.32 (temática, no validada) |
| `ISO-TECH-009` | Protección del código fuente y de ramas | evidence | iso27001 Annex A A.8.4 (temática, no validada) |
| `ISO-ORG-001` | Evaluación de riesgos y Declaración de Aplicabilidad (evidencia organizacional) | evidence | iso27001 Annex A Cláusulas 6.1.2 / 6.1.3 (temática, no validada) |

## Cobertura ASVS del catálogo

El catálogo referencia **80 de 345** requisitos de ASVS 5.0.0 (L1: 44/70, L2: 33/183, L3: 3/92). Esto **no** constituye verificación ni conformidad de ningún nivel de ASVS.

Requisitos referenciados: V1.1.2, V1.2.1, V1.2.4, V1.2.5, V1.3.1, V1.3.2, V1.3.6, V1.5.1, V1.5.2, V2.2.1, V2.2.2, V2.3.1, V2.4.1, V3.2.2, V3.3.1, V3.3.2, V3.3.4, V3.4.1, V3.4.2, V3.4.3, V3.4.4, V3.4.5, V3.5.1, V3.5.2, V3.5.3, V5.2.1, V5.2.2, V5.3.1, V5.3.2, V5.4.1, V5.4.2, V6.3.1, V6.3.2, V6.4.1, V7.2.1, V7.2.2, V7.2.4, V7.4.1, V8.1.1, V8.2.1, V8.2.2, V8.2.3, V8.3.1, V8.4.1, V9.1.1, V9.1.2, V9.1.3, V9.2.1, V9.2.3, V11.3.1, V11.3.2, V11.4.1, V11.4.2, V11.5.1, V12.1.1, V12.2.1, V12.3.2, V13.2.4, V13.2.6, V13.3.1, V13.3.2, V13.4.1, V13.4.2, V14.2.1, V14.2.2, V14.2.6, V15.1.2, V15.2.1, V15.2.2, V15.2.4, V15.3.1, V15.3.2, V15.3.3, V15.3.5, V16.2.5, V16.3.1, V16.3.2, V16.3.3, V16.5.1, V16.5.3
