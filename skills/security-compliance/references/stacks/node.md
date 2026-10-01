# Node.js (NestJS / Express)

Detección: `package.json`; stacks `nestjs` (`@nestjs/core`), `express`. Lockfile: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.

- **NestJS autorización:** `@UseGuards()` por método/controlador **y guards globales** (`APP_GUARD` en módulos, `app.useGlobalGuards`). Un handler sin `@UseGuards` local NO es vulnerable si hay `APP_GUARD`; busca `@Public()`/metadatos que lo excluyan. Revisa `RolesGuard`, `ownership` en servicios.
- **Express:** orden de middlewares (`app.use(auth)` antes de las rutas), routers montados con `router.use(auth)`; `helmet()`, `cors({origin})`, `express-rate-limit`.
- **JWT:** `jsonwebtoken.verify` (no `decode`), `algorithms` explícito, `audience`/`issuer`; secretos desde configuración.
- **Inyección/XSS:** queries concatenadas (`$queryRawUnsafe`, `sequelize.query` con template), `eval`, `child_process.exec` con entrada, `res.send` de HTML con datos sin escape.
- **Prototype pollution/mass assignment:** `Object.assign(entity, req.body)`, `class-validator` con `whitelist`/`forbidNonWhitelisted` en `ValidationPipe`.
- **Config:** `rejectUnauthorized:false`, CORS `origin: true` con `credentials`.
