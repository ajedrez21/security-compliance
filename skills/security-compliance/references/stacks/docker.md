# Docker

Detección: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`. El runner evalúa SEC-INFRA-001 (USER no root en el último stage) y SEC-INFRA-002 (imágenes base fijadas).

- `USER` explícito no root en la imagen final; `USER ${VAR}` no se puede resolver estáticamente (UNKNOWN).
- Base sin versión o `latest` → builds no reproducibles; preferir versión concreta o digest `@sha256:`.
- Secretos: `ARG`/`ENV` con credenciales, `COPY .env`, `ADD http://…` sin verificación; usar BuildKit secrets.
- Paquetes: `curl | sh`, `apt-get install` sin versiones/limpieza, `--privileged` en compose, `docker.sock` montado, puertos innecesarios.
- Multi-stage: lo importante es el stage final; los stages de build pueden ser root.
