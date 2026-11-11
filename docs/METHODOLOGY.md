# Metodología y criterios de análisis

ROVSKA no se limita a listar puertos: clasifica cada hallazgo dentro de marcos
reconocidos para que el informe sea trazable y comparable entre auditorías.

---

## 1. Cadena de trabajo (PTES)

ROVSKA implementa las fases de PTES que pueden automatizarse sin agente:

| Fase PTES | Qué aporta ROVSKA | Evidencia |
| --- | --- | --- |
| `pre-engagement` | Validación de alcance, autorización y límite de hosts. | `scope` en el informe |
| `intelligence-gathering` | ARP, nmap, DNS, SNMP, SMB, WhatWeb, sonda HTTP. | `hosts`, `ports`, `tool_runs` |
| `threat-modeling` | Clasificación de host, exposición y criticidad. | `type`, `risk`, `findings` |
| `vulnerability-analysis` | Nikto, Nuclei, testssl.sh, ssh-audit, reglas EOL/CVE. | `findings` con CVE/CWE |
| `exploitation` | Hydra/Metasploit en `dry-run`; real solo con autorización. | `operations`, `dry_run` |
| `post-exploitation` | **No automatizada.** Se documenta como limitación. | `limitations` |
| `reporting` | JSON, XML, HTML, SARIF y CSV. | `data/reports/` |

La fase de un hallazgo se asigna por señales de contenido (explotación,
reconocimiento, vulnerabilidad) y, como respaldo, por la herramienta de origen.

---

## 2. OSSTMM

Cada hallazgo se mapea a un canal y un módulo:

| Canal | Módulos | Uso en ROVSKA |
| --- | --- | --- |
| Data Networks | `NET-SEC`, `NET-COM`, `NET-APP` | Red, servicios y aplicaciones web. |
| Telecommunications | `TEL-SEC`, `TEL-COM` | Reservado para VoIP/telefonía. |
| Wireless Communications | `WIR-SEC`, `WIR-COM` | Reservado para Wi-Fi. |
| Human Security | `HUM-SEC`, `HUM-SOC` | Reservado para ingeniería social. |
| Physical Security | `PHY-SEC` | Fuera de alcance. |

La asignación actual prioriza `NET-APP` para lo web/TLS, `NET-SEC` para
servicios de red y `NET-COM` como valor por defecto.

---

## 3. OWASP

### Top 10 (2021)

Se asigna una o varias categorías según palabras clave y etiquetas:

| ID | Categoría | Ejemplos que la activan |
| --- | --- | --- |
| A01 | Broken Access Control | acceso, autorización, IDOR, path traversal |
| A02 | Cryptographic Failures | TLS/SSL, certificado, cifrado, texto claro |
| A03 | Injection | XSS, SQLi, inyección de comandos |
| A04 | Insecure Design | diseño, lógica de negocio |
| A05 | Security Misconfiguration | cabeceras, configuración, valores por defecto |
| A06 | Vulnerable and Outdated Components | versiones EOL, componentes desactualizados |
| A07 | Identification and Authentication Failures | login, credenciales, contraseñas |
| A08 | Software and Data Integrity Failures | deserialización, cadena de suministro |
| A09 | Security Logging and Monitoring Failures | logs, monitorización, auditoría |
| A10 | SSRF | SSRF y peticiones del lado servidor |

### WSTG

Se usa el identificador de área (`WSTG-INFO`, `WSTG-CONF`, `WSTG-ATHN`,
`WSTG-ATHZ`, `WSTG-SESS`, `WSTG-INPV`, `WSTG-ERRH`, `WSTG-CRYP`, `WSTG-BUSL`,
`WSTG-CLNT`, `WSTG-APIT`) para agrupar la evidencia web.

---

## 4. CWE y CVE

- **CWE**: se asigna una debilidad principal por hallazgo (p. ej. `CWE-693`
  protección insuficiente, `CWE-1104` componente sin mantenimiento, `CWE-798`
  credenciales embebidas). Si no hay coincidencia, se usa `CWE-693`.
- **CVE**: solo se incluye cuando la versión detectada coincide con una
  vulnerabilidad conocida y verificable (p. ej. vsftpd 2.3.4 →
  `CVE-2011-2523`). Las reglas EOL no inventan CVE.
- **Confianza**: cada hallazgo declara `alta`, `media` o `baja`. Las
  correlaciones por banner son `media`; la coincidencia exacta de versión con
  CVE es `alta`; la inferencia de SO es `baja`.

> Las reglas EOL/CVE son heurísticas. El informe recuerda confirmarlas con los
> avisos oficiales del fabricante.

---

## 5. MITRE ATT&CK

### Tácticas cubiertas

La matriz usa las 14 tácticas Enterprise:

`Reconnaissance`, `Resource Development`, `Initial Access`, `Execution`,
`Persistence`, `Privilege Escalation`, `Defense Evasion`, `Credential Access`,
`Discovery`, `Lateral Movement`, `Collection`, `Command and Control`,
`Exfiltration`, `Impact`.

Solo se muestran técnicas con evidencia; una táctica sin evidencia aparece
vacía, no se rellena artificialmente.

### Asignación

1. El adaptador puede declarar técnicas (`attack=("T1595.002",)`).
2. El hallazgo puede traerlas ya normalizadas.
3. `techniques_for_finding()` añade las derivadas de etiquetas y título.

Ejemplos:

| Hallazgo | Técnica |
| --- | --- |
| Redis/MongoDB expuesto | `T1190` (Exploit Public-Facing Application) |
| SMB accesible | `T1021.002` (SMB/Windows Admin Shares) |
| Credenciales válidas | `T1110` (Brute Force) / `T1078` (Valid Accounts) |
| Escaneo de servicios | `T1595` / `T1595.002` |

### Cadena de ataque (kill chain)

ROVSKA reconstruye siete fases:

1. **Reconocimiento** — hosts, puertos y servicios.
2. **Armamento** — exploits/herramientas candidatas para lo observado.
3. **Entrega** — vectores disponibles (web, VPN, SMB, SSH…).
4. **Explotación** — vulnerabilidades y credenciales validadas.
5. **Instalación** — persistencia: **no evaluada** sin agente.
6. **Mando y control** — **no evaluado** sin agente.
7. **Acciones** — movimiento lateral/exfiltración: **no ejecutado**.

Las fases 5–7 se marcan explícitamente como no evaluadas para no fabricar
evidencia. La cadena es una hipótesis de trabajo, no una prueba de compromiso.

---

## 6. Severidad y riesgo

### Severidad por hallazgo

| Nivel | Peso | Criterio |
| --- | --- | --- |
| CRÍTICO | 30 | Servicio sin autenticación con RCE potencial (Redis, MongoDB, Docker API, Kubelet). |
| ALTO | 15 | Acceso remoto o datos sensibles (SMB, RDP, WinRM, VNC, bases de datos). |
| MEDIO | 6 | Configuración débil o exposición limitada (Proxmox UI, rpcbind, SNMP). |
| BAJO | 2 | Divulgación menor, cabeceras, cookies, páginas por defecto. |
| INFO | 0 | Contexto útil sin impacto directo. |

### Riesgo agregado

- **Host**: suma de pesos de sus hallazgos, tope 100.
- **Global**: suma de pesos de todos los hallazgos, tope 100.
- **Etiqueta**: `Sin hallazgos`, `Informativo`, `Bajo`, `Medio`, `Alto`,
  `Muy alto` o `Crítico` según puntuación y presencia de críticos.

El riesgo es una ayuda de priorización, no una medida estadística de
explotabilidad. La decisión final es del analista.

---

## 7. Comprobaciones positivas

El informe incluye `good_checks`: lo que **sí** está bien. Ejemplos:

- No se detectó SMB expuesto.
- No hay servicios de base de datos accesibles.
- No se observaron credenciales por defecto en los servicios probados.
- El clúster Proxmox aparece con quórum.

Esto evita informes alarmistas y demuestra cobertura.

---

## 8. Perfiles y profundidad

| Perfil | Coste | Ruido | Uso típico |
| --- | --- | --- | --- |
| `discovery` | Bajo | Bajo | Inventario inicial. |
| `quick` | Medio | Medio | Auditoría rutinaria. |
| `full` | Alto | Alto | Búsqueda exhaustiva de puertos. |
| `web` | Medio | Alto | Aplicaciones y TLS. |
| `infra` | Medio | Medio | Servidores y servicios de gestión. |
| `deep` | Alto | Alto | Cadena completa. |
| `attack` | Alto | Muy alto | Validación controlada con autorización. |

Regla práctica: empieza por `discovery`, valida el alcance, y sube de perfil solo
sobre los hosts relevantes.

---

## 9. Informes, comparación e importación

Cada escaneo produce JSON, XML, HTML, PDF, SARIF y CSV desde el mismo objeto
normalizado. El PDF es el entregable formal (portada, resumen ejecutivo,
metodología, hallazgos, ATT&CK y limitaciones); el JSON es la fuente de verdad y
el XML/SARIF/CSV alimentan inventarios, CI y triaje.

La comparativa (`/api/compare`) responde a la pregunta de seguimiento: qué
hosts, puertos y hallazgos aparecen, cuáles se cierran, cuáles cambian de
severidad y cómo evoluciona el riesgo. Solo compara evidencia normalizada; no
inventa remediaciones ni supone que un hallazgo ausente esté corregido si el
escaneo cambió de alcance o de perfil.

La importación acepta informes JSON/XML propios o de terceros y los convierte en
un escaneo normal. Es útil para incorporar auditorías externas, pero el analista
debe revisar la procedencia: ROVSKA conserva el original en
`data/reports/imports/` y marca el escaneo con `stats.imported=true`.

---

## 10. Qué **no** hace ROVSKA

- No explota vulnerabilidades de forma autónoma.
- No mantiene persistencia ni establece C2.
- No exfiltra datos.
- No hace ingeniería social ni pruebas físicas.
- No sustituye una revisión manual de código o configuración.
- No garantiza que un objetivo esté libre de vulnerabilidades: solo informa de
  lo observado con las herramientas y reglas configuradas.

Estas limitaciones se declaran en cada informe (`limitations`) para que el
cliente conozca el alcance real de la auditoría.
