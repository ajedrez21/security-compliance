# SQL y migraciones

Detección: archivos `*.sql`, carpetas de migraciones (Flyway, Liquibase, EF Migrations, Alembic, Knex).

- **Cambios destructivos:** `DROP TABLE/COLUMN`, `TRUNCATE`, `ALTER … DROP`, `DELETE`/`UPDATE` sin `WHERE`; verifica reversibilidad, backup previo y revisión (ITGC-CHG-006 si hay lógica/datos financieros).
- **Privilegios:** `GRANT ALL`, uso de `sa`/`root`/`postgres` por la aplicación; scripts que crean usuarios con contraseña embebida (secreto).
- **Integridad:** restricciones (FK, CHECK, NOT NULL), transacciones en migraciones, índices únicos en claves de negocio.
- **SQL dinámico:** `EXEC(@sql)`/`sp_executesql` con concatenación, funciones que construyen consultas con entrada.
- Reporta lo que no puedes ver: los privilegios reales del rol en la base de datos no se observan desde el código.
