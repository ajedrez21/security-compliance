#!/usr/bin/env python3
"""Genera skills/security-compliance/controls/catalog.json y docs/CONTROL-MAPPING.md.

El catálogo es la fuente de verdad que consume el runner; este script solo evita repetir campos
comunes y valida los mappings ASVS contra controls/baselines.json (IDs oficiales de ASVS 5.0.0).
Uso: python tools/gen_catalog.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "security-compliance"
BASE = json.loads((SKILL / "controls" / "baselines.json").read_text(encoding="utf-8"))["baselines"]
ASVS = BASE["owasp_asvs"]["requirement_levels"]

ASVS_SRC = "OWASP ASVS 5.0.0 (v5.0.0_release), consultado 2026-09-30"
ISO_NOTE = ("Relación temática NO validada contra el texto de ISO/IEC 27001:2022 (norma de pago, "
            "no consultada). Numeración de Annex A según conocimiento público; verificar antes de usar.")
SOX_NOTE = ("Ruleset propio de apoyo; pendiente de validar contra fuentes primarias SEC/PCAOB y la "
            "política de la organización. No es un requisito legal textual.")

STATES = ["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "NOT_RUN", "ERROR"]
CONTROLS = []


def asvs(*ids, thematic=()):
    out = []
    for i in ids:
        if i not in ASVS:
            sys.exit(f"ASVS ID inexistente en la baseline 5.0.0: {i}")
        out.append({"framework": "owasp_asvs", "version": "5.0.0", "ref": i, "type": "exact",
                    "validated": True, "level": ASVS[i], "source": ASVS_SRC})
    for i in thematic:
        out.append({"framework": "owasp_asvs", "version": "5.0.0", "ref": i, "type": "thematic",
                    "validated": True, "source": ASVS_SRC,
                    "note": "El ID existe en la baseline; la relación con el control es temática."})
    return out


def iso(ref, name):
    return [{"framework": "iso27001", "version": "2022", "ref": f"Annex A {ref}", "type": "thematic",
             "validated": False, "source": "https://www.iso.org/standard/27001",
             "note": f"Tema: {name}. " + ISO_NOTE}]


def sox(name):
    return [{"framework": "sox_itgc", "version": "ruleset-1.0", "ref": name, "type": "thematic",
             "validated": False, "source": "pendiente de fuentes primarias SEC/PCAOB", "note": SOX_NOTE}]


def add(cid, title, objective, domain, method, severity, mappings, frameworks, *, procedure=None,
        evidence=None, limits=None, scanner=None, local=None, evidence_types=None, rule=None,
        derived=None, requires_stacks=None, requires_sox=False):
    CONTROLS.append({
        "id": cid, "title": title, "objective": objective, "domain": domain, "version": "1.0.0",
        "frameworks": frameworks,
        "applicability": {"requires_sox_scope": requires_sox, "requires_stacks": requires_stacks or [],
                          "note": ("Aplica solo si el proyecto está en alcance SOX; con alcance desconocido el "
                                   "estado es UNKNOWN." if requires_sox else
                                   ("Se marca NOT_APPLICABLE si no se detecta el stack requerido en el alcance."
                                    if requires_stacks else "Aplica a cualquier proyecto con código de aplicación."))},
        "method": method,
        "scanner_capability": scanner, "local_check": local, "evidence_types": evidence_types or [],
        "evidence_rule": rule, "derived_from": derived or [],
        "review_procedure": procedure or [],
        "evidence_required": evidence or [],
        "states": STATES, "limitations": limits or [], "default_severity": severity,
        "mappings": mappings,
    })


S = ["security", "owasp_asvs"]
SI = ["security", "owasp_asvs", "iso27001"]

# ------------------------------------------------------------------ Seguridad de aplicación
add("SEC-AUTHN-001", "Validación de tokens y emisor/audiencia",
    "Los tokens autoportados (JWT u otros) se verifican con firma, algoritmo permitido, emisor, audiencia y expiración.",
    "security", "agent", "high", asvs("V9.1.1", "V9.1.2", "V9.1.3", "V9.2.1", "V9.2.3"), S,
    procedure=["Localizar dónde se emiten y se verifican tokens (middleware, guards, filtros, librerías).",
               "Comprobar que la firma se verifica (no solo se decodifica) y que existe una lista de algoritmos permitidos (rechazar 'none').",
               "Comprobar validación de iss, aud y exp/nbf; las claves provienen de una fuente de confianza.",
               "Documentar flujo: entrada del token → verificación → uso de claims."],
    evidence=["Fragmentos de código de verificación", "Configuración del validador"],
    limits=["No evalúa la gestión de claves del IdP ni su rotación operativa."])
add("SEC-AUTHN-002", "Sesiones y cookies seguras",
    "Las sesiones se generan, rotan y terminan de forma segura y las cookies usan atributos de protección.",
    "security", "agent", "medium", asvs("V7.2.1", "V7.2.2", "V7.2.4", "V7.4.1", "V3.3.1", "V3.3.2", "V3.3.4"), SI + [],
    procedure=["Identificar el mecanismo de sesión (cookie de sesión, token de referencia).",
               "Verificar atributos Secure/HttpOnly/SameSite, regeneración de sesión al autenticar y terminación en logout.",
               "Revisar revocación/expiración y tiempos de inactividad documentados."],
    limits=["La configuración efectiva de producción puede diferir del código."])
add("SEC-AUTHN-003", "Autenticación: fuerza bruta y cuentas por defecto",
    "Existen controles contra ataques de credenciales y no se dejan cuentas o credenciales por defecto.",
    "security", "agent", "high", asvs("V6.3.1", "V6.3.2", "V6.4.1"), SI,
    procedure=["Buscar flujos de login/registro/recuperación y sus límites de intentos.",
               "Verificar que no existan usuarios o contraseñas por defecto en código, seeds o migraciones.",
               "Verificar que las respuestas no revelen si el usuario existe cuando corresponda."])
add("SEC-AUTHZ-001", "Autorización a nivel de función y de servicio",
    "Cada operación sensible aplica reglas de autorización en una capa de servicio de confianza.",
    "security", "agent", "high", asvs("V8.1.1", "V8.2.1", "V8.3.1"), SI,
    procedure=["Enumerar rutas/handlers y operaciones sensibles (cambios de estado, administración, datos).",
               "Seguir la cadena completa: guards/middleware/filtros globales, políticas, decoradores de clase y servicio.",
               "No marcar vulnerable un handler solo por no tener decorador local si existe un control global o de capa de servicio.",
               "Documentar: entrada, flujo, operación sensible, control existente y condición de explotación."],
    evidence=["Rutas y guards revisados", "Política global de autorización"],
    limits=["La revisión estática no reemplaza pruebas de autorización dinámicas con distintos roles."])
add("SEC-AUTHZ-002", "Acceso por objeto y aislamiento entre tenants",
    "El acceso a cada objeto se restringe según el sujeto y los atributos del recurso; los tenants están aislados.",
    "security", "agent", "high", asvs("V8.2.2", "V8.2.3", "V8.4.1"), SI,
    procedure=["Identificar identificadores de objeto recibidos del cliente (ids en ruta, query, body).",
               "Verificar que la consulta/servicio filtra por propietario/tenant o valida pertenencia (IDOR/BOLA).",
               "Revisar rutas administrativas y accesos entre tenants."],
    limits=["Requiere entender el modelo de datos; sin él, usar UNKNOWN."])
add("SEC-INPUT-001", "Consultas parametrizadas (inyección SQL/NoSQL)",
    "Los datos no confiables nunca se concatenan en consultas; se usan consultas parametrizadas o ORM seguro.",
    "security", "agent", "high", asvs("V1.2.4"), SI,
    procedure=["Buscar construcción de consultas (concatenación, interpolación, raw queries, FromSqlRaw, $queryRaw).",
               "Trazar el origen de los datos hasta la consulta; confirmar si pasa por parámetros.",
               "Registrar los casos con cadenas dinámicas y su fuente (usuario vs constante)."])
add("SEC-INPUT-002", "Codificación de salida y XSS",
    "La salida se codifica según el contexto y el HTML no confiable se sanea.",
    "security", "agent", "medium", asvs("V1.1.2", "V1.2.1", "V1.3.1", "V3.2.2"), SI,
    procedure=["Buscar sinks de HTML (innerHTML, dangerouslySetInnerHTML, v-html, [innerHTML], bypassSecurityTrust*, Html.Raw).",
               "Verificar el origen del dato y si pasa por sanitización/encoding.",
               "Revisar plantillas que desactivan el escape automático."])
add("SEC-INPUT-003", "Inyección de comandos, código dinámico y deserialización",
    "No se ejecutan comandos ni código dinámico con datos no confiables y la deserialización es segura.",
    "security", "agent", "high", asvs("V1.2.5", "V1.3.2", "V1.5.1", "V1.5.2"), SI,
    procedure=["Buscar eval/exec/Function, subprocess con shell, Runtime.exec, Process.Start, pickle/yaml.load/BinaryFormatter.",
               "Trazar el origen de los argumentos; confirmar listas permitidas o escape.",
               "Revisar parsers XML (XXE) y deserializadores de objetos."])
add("SEC-INPUT-004", "Validación de entrada en capa de servicio de confianza",
    "La validación se aplica en el servidor y limita formato, rango y flujo de negocio.",
    "security", "agent", "medium", asvs("V2.2.1", "V2.2.2", "V2.3.1"), S,
    procedure=["Identificar DTOs/modelos de entrada y su validación (pipes, validators, schemas).",
               "Verificar que la validación no depende solo del cliente.",
               "Revisar que flujos de negocio multi-paso verifican el orden/estado."])
add("SEC-API-001", "CORS y CSRF",
    "CORS no confía en orígenes arbitrarios y las operaciones con cookies tienen protección CSRF cuando aplica.",
    "security", "agent", "medium", asvs("V3.4.2", "V3.5.1", "V3.5.2", "V3.5.3"), S,
    procedure=["Revisar configuración CORS (orígenes, credenciales, comodines reflejados).",
               "Si se usan cookies de sesión, verificar tokens anti-CSRF/SameSite en operaciones que cambian estado.",
               "Verificar métodos HTTP apropiados para operaciones sensibles."])
add("SEC-API-002", "SSRF y llamadas a recursos externos",
    "Las solicitudes salientes con URLs controladas por el usuario usan listas de destinos permitidos.",
    "security", "agent", "high", asvs("V1.3.6", "V13.2.4", "V15.3.2"), SI,
    procedure=["Buscar clientes HTTP con URL derivada de entrada (fetch/axios/HttpClient/requests).",
               "Verificar allowlist de hosts, bloqueo de redes internas y redirecciones."])
add("SEC-API-003", "Límites de consumo y anti-automatización",
    "Existen límites de tasa/tamaño para evitar abuso de recursos y automatización excesiva.",
    "security", "agent", "medium", asvs("V2.4.1", "V15.2.2"), S,
    procedure=["Identificar endpoints costosos o de autenticación y los límites aplicados (rate limit, tamaño, paginación)."])
add("SEC-API-004", "Exposición excesiva de datos y mass assignment",
    "Las respuestas devuelven solo los campos necesarios y los modelos no se enlazan ciegamente desde la entrada.",
    "security", "agent", "medium", asvs("V15.3.1", "V15.3.3", "V14.2.6"), S,
    procedure=["Revisar serializadores/DTOs de salida y devolución directa de entidades.",
               "Revisar binding automático de entrada a entidades (campos como role/isAdmin)."])
add("SEC-FILE-001", "Subida de archivos: tamaño, tipo y almacenamiento",
    "Los archivos subidos se limitan por tamaño y tipo y se almacenan fuera de rutas ejecutables.",
    "security", "agent", "medium", asvs("V5.2.1", "V5.2.2", "V5.3.1"), S,
    procedure=["Localizar handlers de upload y sus límites.", "Verificar validación de tipo por contenido y destino de almacenamiento."])
add("SEC-FILE-002", "Nombres de archivo y path traversal",
    "Las rutas construidas con datos del usuario no permiten salir del directorio previsto.",
    "security", "agent", "high", asvs("V5.3.2", "V5.4.1", "V5.4.2"), S,
    procedure=["Buscar construcción de rutas con entrada (path.join, Path.Combine, open) y su normalización/validación."])
add("SEC-SECRETS-001", "Sin secretos embebidos en el alcance",
    "El alcance revisado no contiene credenciales, claves privadas ni tokens en claro.",
    "security", "scanner", "high", asvs(thematic=["V13.3.1"]) + iso("A.8.24", "uso de criptografía y gestión de claves"),
    SI, scanner="secrets",
    evidence=["Resultado del scanner de secretos con versión y alcance"],
    limits=["Un scan del árbol de trabajo no cubre secretos ya presentes en el historial Git.",
            "Las heurísticas de regex aportan candidatos pero no sustituyen al scanner.",
            "Las supresiones inline del scanner (p. ej. gitleaks:allow) se informan como advertencia."])
add("SEC-CRYPTO-001", "Algoritmos criptográficos, hashing y aleatoriedad",
    "Se usan algoritmos aprobados, hashing de contraseñas adecuado y generadores aleatorios seguros.",
    "security", "agent", "high", asvs("V11.3.1", "V11.3.2", "V11.4.1", "V11.4.2", "V11.5.1"), SI,
    procedure=["Buscar MD5/SHA1/DES/ECB, Math.random/random para tokens, hashing de contraseñas.",
               "Verificar uso de bibliotecas validadas y parámetros del KDF."])
add("SEC-CRYPTO-002", "TLS y validación de certificados",
    "Las comunicaciones usan TLS y los clientes validan certificados.",
    "security", "agent", "high", asvs("V12.1.1", "V12.2.1", "V12.3.2"), SI,
    procedure=["Buscar desactivación de verificación (rejectUnauthorized:false, verify=False, ServerCertificateCustomValidationCallback).",
               "Revisar URLs http:// para servicios no locales y configuración TLS de servidores."])
add("SEC-DATA-001", "Datos sensibles y minimización",
    "Los datos sensibles no se envían en URL, no se registran en claro y se minimizan.",
    "security", "agent", "medium", asvs("V14.2.1", "V14.2.2", "V16.2.5"), SI,
    procedure=["Buscar logging de objetos completos, headers de autorización, PII y credenciales.",
               "Verificar que datos sensibles no viajan en query strings ni se cachean."],
    limits=["La clasificación de datos depende de project.contains_pii/contains_financial_data."])
add("SEC-LOG-001", "Eventos de seguridad auditables",
    "Autenticación, fallos de autorización y eventos de seguridad quedan registrados.",
    "security", "agent", "medium", asvs("V16.3.1", "V16.3.2", "V16.3.3"), SI,
    procedure=["Verificar registro de login exitoso/fallido, denegaciones de autorización y cambios administrativos."])
add("SEC-LOG-002", "Manejo de errores y modo debug",
    "Los errores no filtran detalles internos y el modo debug está desactivado en producción.",
    "security", "agent", "medium", asvs("V16.5.1", "V16.5.3", "V13.4.2"), SI,
    procedure=["Revisar manejadores globales de errores, stack traces expuestos y flags DEBUG en configuración productiva."])
add("SEC-WEB-001", "Cabeceras de seguridad del navegador",
    "Las respuestas web incluyen cabeceras de protección apropiadas (HSTS, CSP, nosniff, referrer).",
    "security", "agent", "low", asvs("V3.4.1", "V3.4.3", "V3.4.4", "V3.4.5"), S,
    procedure=["Revisar middleware (helmet, headers de ASP.NET, configuración del proxy) y política CSP."],
    limits=["Las cabeceras efectivas pueden añadirse en un proxy/CDN fuera del repositorio."])
add("SEC-DB-001", "Base de datos: roles mínimos y migraciones destructivas",
    "La aplicación usa cuentas de mínimo privilegio y las migraciones destructivas se identifican y revisan.",
    "security", "agent", "medium", asvs(thematic=["V13.3.2"]) + iso("A.8.3", "restricción de acceso a la información"), SI,
    procedure=["Revisar cadenas/roles de conexión (usuario administrador vs de aplicación).",
               "Listar migraciones con DROP/TRUNCATE/ALTER destructivo y su procedimiento de revisión."],
    limits=["Los privilegios reales en la base de datos no son visibles desde el código."])
add("SEC-SAST-001", "Análisis estático (SAST) sin hallazgos bloqueantes",
    "Un scanner SAST real analiza el alcance y no reporta hallazgos sobre el umbral.",
    "security", "scanner", "medium", asvs(thematic=["V15.3.5"]) + iso("A.8.29", "pruebas de seguridad en desarrollo"), SI,
    scanner="sast", evidence=["Resultado SAST con versión de herramienta y reglas"],
    limits=["Las reglas locales incluidas son un conjunto mínimo propio, no un SAST completo.",
            "Sin un scanner SAST real el control queda NOT_RUN; las heurísticas no lo reemplazan."])
add("SEC-DEPS-001", "Dependencias sin vulnerabilidades conocidas",
    "Las dependencias directas y transitivas se consultan contra una base de vulnerabilidades.",
    "security", "scanner", "high", asvs(thematic=["V15.2.1"]) + iso("A.8.8", "gestión de vulnerabilidades técnicas"), SI,
    scanner="dependencies", evidence=["Resultado del scanner de dependencias, fecha/versión de la base"],
    limits=["La consulta requiere red (network.allow_external_scanners) o una base offline.",
            "Sin lockfile solo se evalúan versiones declaradas, no las resueltas."])
add("SEC-DEPS-002", "Lockfiles presentes para los manifiestos",
    "Cada manifiesto de dependencias tiene un lockfile que fija las versiones resueltas.",
    "security", "local", "low", asvs(thematic=["V15.1.2"]), S, local="lockfiles",
    limits=["Maven no tiene lockfile estándar: esos manifiestos se informan sin evaluar."])
add("SEC-INFRA-001", "Contenedores sin ejecución como root",
    "Los Dockerfiles establecen un usuario no root para el proceso final.",
    "security", "local", "medium", asvs(thematic=["V13.2.6"]) + iso("A.8.9", "gestión de la configuración"), SI,
    local="docker_root", requires_stacks=["docker"],
    limits=["Solo analiza instrucciones USER del último stage; imágenes base con usuario no root implícito requieren revisión manual."])
add("SEC-INFRA-002", "Imágenes base fijadas",
    "Las imágenes base no usan la etiqueta 'latest' ni quedan sin versión.",
    "security", "local", "low", asvs(thematic=["V15.2.4"]) + iso("A.8.9", "gestión de la configuración"), SI,
    local="docker_pin", requires_stacks=["docker"],
    limits=["No verifica digests ni la procedencia de la imagen."])
add("SEC-INFRA-003", "Kubernetes/OpenShift: contexto de seguridad y secretos",
    "Los manifiestos limitan privilegios (runAsNonRoot, sin privileged, límites) y no incluyen secretos en claro.",
    "security", "agent", "medium", asvs(thematic=["V13.2.6"]) + iso("A.8.9", "gestión de la configuración"), SI,
    requires_stacks=["kubernetes", "openshift"],
    procedure=["Revisar securityContext, privileged, hostPath/hostNetwork, capabilities, requests/limits.",
               "Revisar Secrets con data/stringData en claro y variables de entorno con credenciales."],
    limits=["La política efectiva del clúster (admission, SCC) no es visible desde los manifiestos."])
add("SEC-INFRA-004", "Separación de ambientes y configuración",
    "La configuración por ambiente está separada y no mezcla credenciales o endpoints de producción en el código.",
    "security", "agent", "medium", asvs(thematic=["V13.4.1"]) + iso("A.8.31", "separación de entornos"), SI,
    procedure=["Revisar archivos de configuración por ambiente y la gestión de secretos por ambiente."])

# ------------------------------------------------------------------ SOX / ITGC (evidencia de proceso)
ITGC = ["sox_itgc"]
add("ITGC-CHG-001", "Trazabilidad ticket → cambio → PR",
    "Cada cambio en alcance se vincula a un requerimiento/ticket y a un PR identificables.",
    "itgc", "evidence", "medium", sox("Gestión de cambios: trazabilidad"), ITGC, requires_sox=True,
    evidence_types=["pr_metadata"], rule="traceability",
    evidence=["Metadatos del PR con tickets vinculados"],
    limits=["La existencia de un ticket no prueba su aprobación ni su vigencia."])
add("ITGC-CHG-002", "Aprobación independiente vigente sobre el cambio efectivo",
    "El cambio fue aprobado por una persona distinta del autor y la aprobación corresponde al commit final.",
    "itgc", "evidence", "high", sox("Gestión de cambios: aprobación independiente"), ITGC, requires_sox=True,
    evidence_types=["pr_approval"], rule="approval",
    evidence=["Aprobaciones con actor, estado y commit asociado"],
    limits=["La identidad del aprobador no se verifica sin un conector autenticado; el autor de un commit no es una identidad autenticada."])
add("ITGC-CHG-003", "Resultados de pruebas vinculados al commit exacto",
    "Las pruebas automatizadas se ejecutaron con éxito sobre el commit evaluado.",
    "itgc", "evidence", "high", sox("Gestión de cambios: pruebas"), ITGC, requires_sox=True,
    evidence_types=["ci_run"], rule="ci_test",
    evidence=["Ejecución de CI con conclusión y commit_sha"],
    limits=["La presencia de un workflow no prueba que se haya ejecutado con éxito."])
add("ITGC-CHG-004", "Protección de ramas sin bypass",
    "La rama de integración exige revisión y no permite omitirla sin registro.",
    "itgc", "evidence", "high", sox("Gestión de cambios: protección de ramas y de su política"), ITGC, requires_sox=True,
    evidence_types=["branch_protection"], rule="branch_protection",
    evidence=["Configuración de protección de rama exportada del proveedor"],
    limits=["Una rama local no prueba protección remota; el workflow/CODEOWNERS no equivale a la configuración del proveedor."])
add("ITGC-CHG-005", "Despliegue trazable al artefacto y al commit",
    "Cada despliegue registra artefacto/commit desplegado, aprobador y ejecutor.",
    "itgc", "evidence", "medium", sox("Gestión de cambios: despliegue"), ITGC, requires_sox=True,
    evidence_types=["deployment_record"], rule="deployment",
    evidence=["Registro de despliegue con commit, artefacto, aprobador y ejecutor"])
add("ITGC-CHG-006", "Revisión de cambios a base de datos y lógica financiera",
    "Las migraciones y cambios a lógica financiera, reportes o integridad de datos reciben revisión específica.",
    "itgc", "agent", "high", sox("Gestión de cambios: cambios de datos y lógica crítica"), ITGC, requires_sox=True,
    procedure=["Identificar migraciones y módulos de cálculo/reporte financiero en el diff.",
               "Revisar integridad (transacciones, restricciones), reversibilidad y pruebas asociadas.",
               "Registrar qué quedó sin evidencia de revisión humana."],
    limits=["La revisión del agente no reemplaza la aprobación independiente (ITGC-CHG-002)."])
add("ITGC-CHG-007", "Cambios de emergencia con evidencia posterior",
    "Si la política admite cambios de emergencia, existe evidencia de revisión posterior.",
    "itgc", "evidence", "medium", sox("Gestión de cambios: cambios de emergencia"), ITGC, requires_sox=True,
    evidence_types=["emergency_change"], rule="emergency",
    limits=["Depende de itgc.emergency_change_policy; con 'unknown' el estado es UNKNOWN."])
add("ITGC-ACC-001", "Separación de funciones y revisión de accesos",
    "Los accesos a repositorio, CI y producción siguen mínimo privilegio y separación de funciones.",
    "itgc", "evidence", "high", sox("Acceso y segregación de funciones"), ITGC, requires_sox=True,
    evidence_types=["access_review"], rule="access_review",
    evidence=["Revisión de accesos con alcance, revisor y resultado"])
add("ITGC-OPS-001", "Backups y restauración",
    "Existe evidencia de respaldos y pruebas de restauración de sistemas en alcance.",
    "itgc", "evidence", "medium", sox("Operaciones: backups"), ITGC, requires_sox=True,
    evidence_types=["operation_evidence"], rule="backup", evidence=["Evidencia de backup/restauración"])
add("ITGC-OPS-002", "Tareas programadas y atención de fallos",
    "Las tareas programadas críticas se monitorean y sus fallos se atienden.",
    "itgc", "evidence", "medium", sox("Operaciones: procesamiento programado"), ITGC, requires_sox=True,
    evidence_types=["operation_evidence"], rule="scheduled_jobs", evidence=["Evidencia de monitoreo de jobs"])

# ------------------------------------------------------------------ ISO/IEC 27001 (controles técnicos)
ISOF = ["iso27001"]
add("ISO-TECH-001", "Control de acceso y autenticación en la aplicación",
    "Resumen técnico de autenticación y autorización de la aplicación.", "iso", "derived", "high",
    iso("A.8.5 / A.5.15", "autenticación segura y control de acceso"), ISOF,
    derived=["SEC-AUTHN-001", "SEC-AUTHN-002", "SEC-AUTHN-003", "SEC-AUTHZ-001", "SEC-AUTHZ-002"],
    limits=["Estado derivado de controles SEC; no evalúa la política de control de acceso de la organización."])
add("ISO-TECH-002", "Gestión de vulnerabilidades técnicas",
    "Resumen técnico de SAST y dependencias.", "iso", "derived", "high",
    iso("A.8.8", "gestión de vulnerabilidades técnicas"), ISOF, derived=["SEC-SAST-001", "SEC-DEPS-001", "SEC-DEPS-002"])
add("ISO-TECH-003", "Configuración segura de infraestructura",
    "Resumen técnico de contenedores y manifiestos.", "iso", "derived", "medium",
    iso("A.8.9", "gestión de la configuración"), ISOF,
    derived=["SEC-INFRA-001", "SEC-INFRA-002", "SEC-INFRA-003", "SEC-INFRA-004"])
add("ISO-TECH-004", "Registro, errores y datos sensibles",
    "Resumen técnico de logging y manejo de datos.", "iso", "derived", "medium",
    iso("A.8.15", "registro de eventos"), ISOF, derived=["SEC-LOG-001", "SEC-LOG-002", "SEC-DATA-001"])
add("ISO-TECH-005", "Criptografía y gestión de secretos",
    "Resumen técnico de criptografía y secretos.", "iso", "derived", "high",
    iso("A.8.24", "uso de criptografía"), ISOF, derived=["SEC-CRYPTO-001", "SEC-CRYPTO-002", "SEC-SECRETS-001"])
add("ISO-TECH-006", "Codificación segura",
    "Resumen técnico de validación, inyección, archivos y APIs.", "iso", "derived", "high",
    iso("A.8.28", "codificación segura"), ISOF,
    derived=["SEC-INPUT-001", "SEC-INPUT-002", "SEC-INPUT-003", "SEC-INPUT-004", "SEC-API-001", "SEC-API-002",
             "SEC-API-003", "SEC-API-004", "SEC-FILE-001", "SEC-FILE-002"])
add("ISO-TECH-007", "Pruebas de seguridad ejecutadas sobre el commit",
    "Existe evidencia de pruebas de seguridad en CI asociadas al commit evaluado.", "iso", "evidence", "medium",
    iso("A.8.29", "pruebas de seguridad en desarrollo y aceptación"), ISOF,
    evidence_types=["ci_run"], rule="security_ci", evidence=["Ejecución de CI de seguridad con commit_sha"])
add("ISO-TECH-008", "Gestión de cambios técnica (revisión y pruebas)",
    "El cambio fue revisado y probado antes de integrarse (independiente de SOX).", "iso", "evidence", "medium",
    iso("A.8.32", "gestión de cambios"), ISOF, evidence_types=["pr_approval", "ci_run"], rule="change_mgmt")
add("ISO-TECH-009", "Protección del código fuente y de ramas",
    "El acceso y los cambios al código fuente están protegidos por la configuración del repositorio.", "iso", "evidence",
    "medium", iso("A.8.4", "acceso al código fuente"), ISOF, evidence_types=["branch_protection"],
    rule="branch_protection")
add("ISO-ORG-001", "Evaluación de riesgos y Declaración de Aplicabilidad (evidencia organizacional)",
    "El sistema de gestión mantiene evaluación de riesgos y SoA vigentes. No es un control técnico del sistema.",
    "iso", "evidence", "info", iso("Cláusulas 6.1.2 / 6.1.3", "evaluación y tratamiento de riesgos, SoA"), ISOF,
    evidence_types=["organizational"], rule="organizational",
    limits=["Fuera del alcance de una revisión técnica del código; se informa como UNKNOWN sin evidencia aportada."])

catalog = {"schema_version": 1, "catalog_version": "1.0.0", "baselines": {
    "owasp_asvs": BASE["owasp_asvs"]["version"], "iso27001": BASE["iso27001"]["version"],
    "sox_itgc": BASE["sox_itgc"]["version"]}, "controls": CONTROLS}

ids = [c["id"] for c in CONTROLS]
assert len(ids) == len(set(ids)), "IDs duplicados"
for c in CONTROLS:
    for d in c["derived_from"]:
        assert d in ids, f"{c['id']} deriva de un control inexistente {d}"
(SKILL / "controls" / "catalog.json").write_text(json.dumps(catalog, indent=1, ensure_ascii=False) + "\n",
                                                  encoding="utf-8")

# ---- docs/CONTROL-MAPPING.md
lines = ["# Mapeo de controles", "",
         "Generado por `tools/gen_catalog.py` desde `skills/security-compliance/controls/catalog.json`. "
         "No editar a mano.", "",
         "- **exact (validada)**: el ID existe en la baseline oficial indicada (verificado contra los datos "
         "publicados) y expresa el tema del control.",
         "- **thematic**: relación temática; no implica equivalencia. Los mappings ISO/IEC 27001:2022 y SOX/ITGC "
         "están **pendientes de validación** (ver `docs/SOURCES.md`).",
         "- Los IDs `SEC-*`, `ITGC-*`, `ISO-*` son identificadores propios de este producto, no numeración oficial.", ""]
for dom, title in (("security", "Seguridad de aplicación"), ("itgc", "SOX / ITGC (ruleset propio)"),
                   ("iso", "ISO/IEC 27001 (controles técnicos y evidencia organizacional)")):
    lines += [f"## {title}", "", "| ID | Control | Método | Mappings |", "|---|---|---|---|"]
    for c in CONTROLS:
        if c["domain"] != dom:
            continue
        mp = []
        for m in c["mappings"]:
            tag = "exacta" if m["type"] == "exact" else "temática"
            if not m["validated"]:
                tag += ", no validada"
            mp.append(f"{m['framework']} {m['ref']} ({tag})")
        lines.append(f"| `{c['id']}` | {c['title']} | {c['method']} | {'; '.join(mp) or '—'} |")
    lines.append("")
asvs_ids = sorted({m["ref"] for c in CONTROLS for m in c["mappings"] if m["framework"] == "owasp_asvs"},
                  key=lambda s: [int(x) for x in s[1:].split(".")])
by_level = {1: 0, 2: 0, 3: 0}
for i in asvs_ids:
    by_level[ASVS[i]] += 1
tot = {1: 0, 2: 0, 3: 0}
for v in ASVS.values():
    tot[v] += 1
lines += ["## Cobertura ASVS del catálogo", "",
          f"El catálogo referencia **{len(asvs_ids)} de {len(ASVS)}** requisitos de ASVS 5.0.0 "
          f"(L1: {by_level[1]}/{tot[1]}, L2: {by_level[2]}/{tot[2]}, L3: {by_level[3]}/{tot[3]}). "
          "Esto **no** constituye verificación ni conformidad de ningún nivel de ASVS.", "",
          "Requisitos referenciados: " + ", ".join(asvs_ids), ""]
(ROOT / "docs" / "CONTROL-MAPPING.md").write_text("\n".join(lines), encoding="utf-8")
print(f"{len(CONTROLS)} controles; {len(asvs_ids)} requisitos ASVS referenciados")
