# Guía de revisión por área (para los controles de método `agent`)

Principio: **traza el flujo, no busques patrones sueltos.** Para cada hallazgo documenta: entrada → flujo → operación sensible → control existente → condición de explotación. Si no puedes completarlo, reporta `UNKNOWN` o confianza `low`.

| Área | Qué comprobar | Falsos positivos frecuentes |
|---|---|---|
| Autenticación y sesiones (SEC-AUTHN-*) | Firma verificada (no solo decodificada), algoritmos permitidos, `iss`/`aud`/`exp`; cookies Secure/HttpOnly/SameSite; rotación al autenticar; logout/revocación | Validación hecha en un gateway/proxy fuera del repo (indícalo como limitación) |
| Autorización (SEC-AUTHZ-*) | Guards/middleware/filtros **globales**, políticas, decoradores de clase y capa de servicio; acceso por objeto (IDOR) y por tenant | Handler sin decorador local pero con guard global o policy por defecto |
| Entradas y salidas (SEC-INPUT-*) | Consultas parametrizadas; sinks HTML (`innerHTML`, `dangerouslySetInnerHTML`, `Html.Raw`); eval/exec/shell; deserialización insegura; XXE | Concatenación de constantes; datos que provienen de enums validados |
| APIs (SEC-API-*) | CORS con orígenes explícitos; CSRF si hay cookies; SSRF con allowlist; límites de consumo; DTOs de salida; mass assignment | CORS abierto solo en entornos de desarrollo configurados por perfil |
| Archivos (SEC-FILE-*) | Tamaño/tipo por contenido; normalización de rutas; almacenamiento fuera de rutas ejecutables | Rutas construidas solo con constantes |
| Secretos y criptografía (SEC-SECRETS-001, SEC-CRYPTO-*) | Credenciales embebidas (scanner), hashing de contraseñas con KDF, aleatoriedad criptográfica, TLS verificado | MD5/SHA1 para checksums no criptográficos |
| Datos y logging (SEC-DATA-001, SEC-LOG-*) | PII/credenciales en logs, errores genéricos al cliente, eventos de seguridad auditables | Logs de depuración deshabilitados en producción por perfil |
| Base de datos (SEC-DB-001) | Rol de aplicación de mínimo privilegio, migraciones destructivas (DROP/TRUNCATE) y su revisión | Migraciones de entorno de pruebas |
| Supply chain (SEC-DEPS-*) | Lockfiles, vulnerabilidades por scanner, versiones fijadas | Vulnerabilidades en dependencias de desarrollo no empaquetadas |
| Infraestructura (SEC-INFRA-*) | Dockerfile: `USER` no root, base fijada, secretos; K8s/OpenShift: `securityContext`, `privileged`, límites, Secrets en claro; separación de ambientes | Imágenes de build multi-stage cuyo stage final sí es no root |

## Severidad

Deriva del **impacto y la exposición**, no del patrón. Ejemplos: SQLi alcanzable sin autenticación → `critical/high`; el mismo patrón en una herramienta interna detrás de autenticación fuerte → menor. No inventes CVSS; cita un CVE solo si lo informó un scanner identificable.

## Qué debe contener tu `review.json`

`control_results[]` con `status` + `rationale` (≥10 caracteres), `files_examined` para `PASS`, `finding_refs` para `FAIL`, y `findings[]` con archivo y línea reales, descripción y `flow`. Si un control depende de configuración que no ves (gateway, IdP, CDN), usa `UNKNOWN` y explícalo en `limitations`.
