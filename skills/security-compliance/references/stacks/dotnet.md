# .NET (ASP.NET Core)

Detección: `*.csproj`, `*.sln`. Lockfile opcional: `packages.lock.json`.

- **Autenticación/tokens:** `AddJwtBearer` → `TokenValidationParameters` (`ValidateIssuer/Audience/Lifetime/IssuerSigningKey` en `true`; sin `RequireSignedTokens=false`). Cookies: `CookieAuthenticationOptions` (`SecurePolicy`, `HttpOnly`, `SameSite`).
- **Autorización:** `[Authorize]` en controlador/acción, `FallbackPolicy`/`DefaultPolicy` globales (`RequireAuthenticatedUser`), `AuthorizationHandler`, `[AllowAnonymous]` explícito. Revisa endpoints minimal API (`.RequireAuthorization()`), filtros globales y `MapControllers().RequireAuthorization()`.
- **IDOR:** consultas con `Id` del request sin filtro por usuario/tenant; `AsNoTracking().FirstAsync(x => x.Id == id)` sin chequeo de propiedad.
- **Inyección:** `FromSqlRaw`/`ExecuteSqlRaw` con interpolación (usar `FromSqlInterpolated`/parámetros), Dapper con concatenación.
- **XSS:** `Html.Raw`, `@Html.Raw`; `[ValidateAntiForgeryToken]`/`AutoValidateAntiforgeryToken` para formularios con cookies.
- **Cripto/otros:** `MD5.Create`, `SHA1.Create`, `BinaryFormatter`, `ServerCertificateCustomValidationCallback = (…) => true`, `DeveloperExceptionPage` fuera de Development, `AllowAnyOrigin()` + `AllowCredentials()`.
- **Secretos:** `appsettings*.json` con cadenas de conexión/keys; usar User Secrets/Key Vault.
