# Java (Spring / Jakarta)

Detección: `pom.xml`, `build.gradle(.kts)`. Maven no tiene lockfile estándar (no evaluable); Gradle: `gradle.lockfile`.

- **Autorización:** Spring Security `SecurityFilterChain` (`authorizeHttpRequests`, `anyRequest().authenticated()`), `@PreAuthorize`/`@Secured`, `@EnableMethodSecurity`; ojo con `permitAll()` y `csrf().disable()` en APIs con cookies.
- **Inyección:** `createQuery`/`createNativeQuery` con concatenación, `JdbcTemplate` con strings dinámicos, `Runtime.exec`, `ObjectInputStream` sin filtros, parsers XML sin `disallow-doctype-decl`.
- **Cripto/TLS:** `MessageDigest.getInstance("MD5"/"SHA-1")`, `TrustManager` permisivo, `HostnameVerifier` que retorna `true`.
- **Config:** `management.endpoints.web.exposure.include=*`, `spring.h2.console.enabled`, credenciales en `application*.properties`.
