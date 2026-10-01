# Frontend (React / Next / Angular)

Detección: `react`, `next`, `@angular/core` en `package.json`.

- **XSS:** `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, Angular `bypassSecurityTrust*`, `[innerHTML]`; sanitización (DOMPurify/DomSanitizer) previa.
- **Tokens en el navegador:** `localStorage`/`sessionStorage` para tokens de sesión (prefiere cookies `HttpOnly`); datos autenticados en caché/storage tras logout.
- **Next.js:** rutas API/route handlers y Server Actions con autenticación y autorización propias; `middleware.ts` no es suficiente por sí solo para autorización de datos; variables `NEXT_PUBLIC_*` no deben contener secretos.
- **Redirecciones:** `window.location`/`router.push` con URL de entrada (open redirect), `postMessage` sin verificar `origin`.
- **Cabeceras/CSP:** configuración en `next.config.js`/servidor; el frontend estático puede recibir cabeceras desde el CDN (limitación).
