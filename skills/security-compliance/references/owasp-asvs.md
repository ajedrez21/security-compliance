# OWASP ASVS — baseline y uso

- **Baseline:** ASVS 5.0.0 (release `v5.0.0_release`, 2025-05-30; 345 requisitos). IDs y niveles verificados contra los datos oficiales y guardados en `controls/baselines.json`. No se actualiza en silencio.
- **Catálogo:** cada control `SEC-*` referencia requisitos concretos (`type: exact`, validado) o relaciones temáticas. La lista exacta está en `docs/CONTROL-MAPPING.md` (80 de 345 requisitos referenciados).
- **Nivel objetivo (`review.asvs_target_level`):** solo filtra la estadística de cobertura; **no** certifica un nivel ni implica cobertura completa. Para declarar un nivel habría que verificar cada requisito aplicable.
- **No confundir** OWASP Top 10 con ASVS.
- Capítulos 5.0.0: V1 Codificación y sanitización, V2 Validación y lógica de negocio, V3 Seguridad del frontend web, V4 API y servicios web, V5 Manejo de archivos, V6 Autenticación, V7 Sesiones, V8 Autorización, V9 Tokens autoportados, V10 OAuth/OIDC, V11 Criptografía, V12 Comunicación segura, V13 Configuración, V14 Protección de datos, V15 Codificación segura y arquitectura, V16 Logging y errores, V17 WebRTC.
- Sin cubrir en esta versión: V10 (OAuth/OIDC), V17 (WebRTC) y la mayoría de requisitos L3.
