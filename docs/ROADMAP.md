# Hoja de ruta

Mejoras ordenadas por impacto y riesgo. Cada bloque indica el criterio de
aceptación para que se pueda cerrar sin ambigüedad.

Leyenda: **P0** bloquea un uso profesional; **P1** mejora el producto;
**P2** amplía cobertura metodológica; **P3** escala la plataforma.

---

## P0 — Antes de usar con un cliente

| # | Mejora | Por qué | Criterio de aceptación |
| --- | --- | --- | --- |
| 1 | Construir y validar la imagen Kali | Los adaptadores están escritos, pero no probados contra las versiones reales de las herramientas. | ✅ **Hecho (2026-11-01):** imagen construida, `doctor` 16/16, escaneos `quick` y `web` reales, dry-run de Hydra/Metasploit. |
| 2 | Tests de parseo con fixtures | Un cambio de formato de `nmap`/`nuclei` rompería el análisis sin avisar. | ⏳ **Parcial:** SMB, SNMP, testssl, masscan y Metasploit cubiertos; faltan fixtures de nmap, Nuclei, Nikto, WhatWeb y ffuf. |
| 3 | Migraciones de base de datos | `CREATE TABLE IF NOT EXISTS` no cubre cambios de columnas. | Tabla `schema_migrations`, script `rovvska migrate` y test de actualización desde la versión anterior. |
| 4 | Backups y retención | Los informes son evidencia; perderlos invalida la auditoría. | `make backup` genera copia consistente de SQLite + reports; política de retención documentada. |
| 5 | Autenticación del panel | El token actual es único y opcional; no hay usuarios ni roles. | Login con usuario/contraseña (hash `scrypt`), roles `admin`/`auditor`/`lector`, sesión con expiración. |
| 6 | TLS y proxy | El panel no debe ir por HTTP fuera de localhost. | Documentación y ejemplo de Caddy/nginx con TLS, HSTS y autenticación básica o OIDC. |
| 7 | Cancelación y timeouts verificados | Un escaneo colgado bloquea recursos. | Test de cancelación en < 2 s; timeout por herramienta y global; estado `cancelled` consistente. |
| 8 | Revisión de seguridad del propio ROVSKA | Es una herramienta ofensiva: su superficie importa. | Checklist OWASP ASVS aplicada a la API; fuzzing de endpoints; sin traversal en estáticos. |

---

## P1 — Producto

| # | Mejora | Detalle |
| --- | --- | --- |
| 9 | Informe PDF | ✅ **Hecho (2026-11-02):** WeasyPrint 70.0 dentro de Kali, A4, portada, resumen ejecutivo, metodología, hallazgos, ATT&CK, cabeceras/pies y numeración. Pendiente: firmas y anexos configurables. |
| 10 | Evidencia firmada | Hash-chain de eventos + firma detached (Ed25519) del JSON final para demostrar integridad. |
| 11 | Comparativa entre escaneos | ✅ **Hecho (2026-11-02):** diff de hosts/puertos/hallazgos y cambios de severidad, delta de riesgo, técnicas ATT&CK y vista “Comparativa” en el panel. |
| 12 | Inventario de activos | Etiquetas, propietario, criticidad de negocio, entorno (prod/pre), agrupación por sede. |
| 13 | Programación | Escaneos recurrentes con ventana horaria, límite de concurrencia y notificación de cambios. |
| 14 | Notificaciones | Webhook genérico, correo SMTP y Slack/Teams para hallazgos críticos y fin de escaneo. |
| 15 | Flujo de aprobación | Un `operator` propone y un `approver` autoriza operaciones de ataque; queda registro de quién aprobó qué. |
| 16 | Exportadores | DefectDojo, Jira, ServiceNow, OCSF/CEF para SIEM, y CSV por host. |
| 17 | Búsqueda y filtros avanzados | Por CVE, CWE, técnica, etiqueta, confianza, estado de remediación y propietario. |
| 18 | Gestión de remediación | Estado por hallazgo (abierto, en curso, aceptado, falso positivo), comentarios y fecha objetivo. |
| 19 | Multi-idioma | Interfaz y plantillas de informe en ES/EN. |

---

## P2 — Cobertura metodológica

| # | Mejora | Detalle |
| --- | --- | --- |
| 20 | CVSS 3.1 / 4.0 | Puntuación vectorial por hallazgo, además de la severidad cualitativa. |
| 21 | EPSS y CISA KEV | Importación offline de feeds (CSV/JSON) para priorizar por explotación real. Sin llamadas en tiempo de escaneo. |
| 22 | Catálogos versionados | ATT&CK, CWE y OWASP con versión explícita y fecha de actualización en el informe. |
| 23 | OSSTMM completo | Cálculo de RAV y controles por módulo, no solo etiquetado. |
| 24 | OWASP ASVS | Mapeo de controles verificables y estado (cumple/no cumple/no aplica). |
| 25 | Rutas de ataque | Grafo de relaciones host→servicio→credencial→posible movimiento lateral, con ruta más probable. |
| 26 | Active Directory | Enumeración LDAP/Kerberos, ACLs, Kerberoasting (dry-run) y rutas a DA. |
| 27 | Cloud y Kubernetes | AWS/Azure/GCP (postura), K8s (RBAC, secrets, admission) y contenedores. |
| 28 | Wi-Fi y VoIP | Canales OSSTMM hoy reservados; requiere hardware y alcance específico. |
| 29 | Cumplimiento | Mapeo a ISO 27001, NIS2, ENS y PCI DSS para el mismo hallazgo. |
| 30 | Playbooks | Guías de validación manual por hallazgo, con comandos y criterios de falso positivo. |

---

## P3 — Escala

| # | Mejora | Detalle |
| --- | --- | --- |
| 31 | PostgreSQL | Sustituir SQLite cuando haya varios operadores o retención larga. Mantener SQLite como modo “standalone”. |
| 32 | Cola distribuida | Workers separados para escaneos largos, con reintentos y prioridades. |
| 33 | Multi-tenant | Organizaciones, usuarios, alcance por cliente y aislamiento de datos. |
| 34 | API keys y cuotas | Claves por integración, permisos granulares y rate limiting. |
| 35 | Auditoría inmutable | Append-only con hash-chain y exportación a WORM/S3 Object Lock. |
| 36 | Despliegue | Imágenes firmadas, SBOM, escaneo de la propia imagen y despliegue con Compose/Helm. |
| 37 | Observabilidad | Métricas Prometheus, trazas OpenTelemetry y dashboards de salud. |

---

## IA y orquestación

| # | Mejora | Detalle |
| --- | --- | --- |
| 38 | Modelo local | Opción Ollama/vLLM para no enviar contexto a terceros. |
| 39 | Evaluación de planes | Suite de prompts con planes esperados; medir precisión, herramientas inválidas y pasos fuera de alcance. |
| 40 | Pruebas de prompt injection | Fixtures con banners maliciosos; verificar que el plan no se desvía y que se rechaza. |
| 41 | Aprobación humana obligatoria | Para cualquier paso con `risk=attack`, el plan queda en `pending_approval`. |
| 42 | Explicabilidad | Cada paso del plan incluye `why`, evidencia que lo justifica y técnica ATT&CK esperada. |

---

## Decisiones pendientes

Estas elecciones cambian el alcance del producto y conviene resolverlas antes de
invertir en P1/P2:

1. **¿PDF nativo o HTML imprimible?** PDF nativo requiere una dependencia
   (WeasyPrint) o un navegador headless. El HTML actual ya es imprimible.
2. **¿Autenticación local o SSO?** Usuarios locales con `scrypt` es autónomo;
   OIDC encaja en empresas pero añade configuración.
3. **¿SQLite o PostgreSQL?** SQLite es suficiente para un operador; PostgreSQL
   es mejor para equipo, historial largo y concurrencia.
4. **¿Hasta dónde llega la explotación?** Validación de credenciales y módulos
   `auxiliary` es defendible; explotación con payload y post-explotación cambia
   el encuadre legal y operativo.
5. **¿Se permite IA en la nube?** Si no, el orquestador debe usar un modelo local
   o quedarse en el plan determinista.
6. **¿Multi-cliente?** Determina si hace falta multi-tenant desde el principio o
   se puede posponer.

---

## Orden recomendado

```
P0 (1→8)  →  P1 (10,15)  →  P2 (20,21,25)  →  P1 resto  →  P3
```

La razón: primero se valida que las herramientas reales funcionan y que la
evidencia es íntegra; después se mejora el entregable y el flujo de aprobación;
por último se amplía cobertura y escala.
