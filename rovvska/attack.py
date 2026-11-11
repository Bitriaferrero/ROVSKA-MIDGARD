#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MITRE ATT&CK: catálogo, mapeo de hallazgos, matriz y cadena de ataque.

El catálogo es un subconjunto práctico de Enterprise ATT&CK centrado en
reconocimiento, acceso inicial, credenciales, descubrimiento y movimiento
lateral, que es lo que ROVSKA puede evidenciar desde la red.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Finding, Host, SEV_ORDER, normalize_severity


TACTICS: list[tuple[str, str, str]] = [
    ("reconnaissance", "Reconnaissance", "Recon"),
    ("resource-development", "Resource Development", "ResDev"),
    ("initial-access", "Initial Access", "Initial"),
    ("execution", "Execution", "Exec"),
    ("persistence", "Persistence", "Persist"),
    ("privilege-escalation", "Privilege Escalation", "PrivEsc"),
    ("defense-evasion", "Defense Evasion", "DefEvas"),
    ("credential-access", "Credential Access", "Cred"),
    ("discovery", "Discovery", "Disc"),
    ("lateral-movement", "Lateral Movement", "Lateral"),
    ("collection", "Collection", "Collect"),
    ("command-and-control", "Command and Control", "C2"),
    ("exfiltration", "Exfiltration", "Exfil"),
    ("impact", "Impact", "Impact"),
]

TACTIC_ORDER = {tid: i for i, (tid, _, _) in enumerate(TACTICS)}
TACTIC_NAMES = {tid: name for tid, name, _ in TACTICS}

TECHNIQUES: dict[str, dict] = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "reconnaissance", "phase": "recon",
              "desc": "Escanear redes y servicios de forma activa."},
    "T1595.001": {"name": "Scanning IP Blocks", "tactic": "reconnaissance", "phase": "recon",
                  "desc": "Barrido de bloques de IP para localizar hosts."},
    "T1595.002": {"name": "Vulnerability Scanning", "tactic": "reconnaissance", "phase": "recon",
                  "desc": "Búsqueda activa de vulnerabilidades y versiones."},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "reconnaissance", "phase": "recon",
              "desc": "Recopilar información de hosts, software y configuración."},
    "T1592.002": {"name": "Software", "tactic": "reconnaissance", "phase": "recon",
                  "desc": "Identificar productos y versiones de software."},
    "T1590": {"name": "Gather Victim Network Information", "tactic": "reconnaissance", "phase": "recon",
              "desc": "Recopilar topología, rangos y servicios de la red."},
    "T1590.004": {"name": "Network Topology", "tactic": "reconnaissance", "phase": "recon",
                  "desc": "Descubrir la topología y segmentación de la red."},
    "T1590.005": {"name": "IP Addresses", "tactic": "reconnaissance", "phase": "recon",
                  "desc": "Identificar direcciones IP y rangos."},
    "T1596": {"name": "Search Open Technical Databases", "tactic": "reconnaissance", "phase": "recon",
              "desc": "Consultar bases de datos abiertas (CVE, exploits, DNS)."},
    "T1596.005": {"name": "Scan Databases", "tactic": "reconnaissance", "phase": "recon",
                  "desc": "Buscar en bases de datos de escaneos y vulnerabilidades."},
    "T1593": {"name": "Search Open Websites/Domains", "tactic": "reconnaissance", "phase": "recon",
              "desc": "Buscar información pública en webs y dominios."},
    "T1594": {"name": "Search Victim-Owned Websites", "tactic": "reconnaissance", "phase": "recon",
              "desc": "Analizar la web propia del objetivo."},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "reconnaissance", "phase": "recon",
              "desc": "Recopilar identidades, correos y credenciales."},
    "T1589.001": {"name": "Credentials", "tactic": "reconnaissance", "phase": "recon",
                  "desc": "Buscar credenciales expuestas."},

    # Resource Development
    "T1588": {"name": "Obtain Capabilities", "tactic": "resource-development", "phase": "recon",
              "desc": "Obtener herramientas y exploits."},
    "T1588.005": {"name": "Exploits", "tactic": "resource-development", "phase": "recon",
                  "desc": "Obtener exploits para vulnerabilidades conocidas."},
    "T1588.002": {"name": "Tool", "tactic": "resource-development", "phase": "recon",
                  "desc": "Seleccionar herramientas de ataque."},

    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access", "phase": "exploit",
              "desc": "Explotar un servicio expuesto (web, VPN, correo...)."},
    "T1133": {"name": "External Remote Services", "tactic": "initial-access", "phase": "exploit",
              "desc": "Acceder mediante VPN, RDP, SSH u otros servicios remotos."},
    "T1078": {"name": "Valid Accounts", "tactic": "initial-access", "phase": "exploit",
              "desc": "Uso de cuentas válidas para acceder."},
    "T1078.001": {"name": "Default Accounts", "tactic": "initial-access", "phase": "exploit",
                  "desc": "Cuentas por defecto o contraseñas débiles."},
    "T1078.002": {"name": "Domain Accounts", "tactic": "initial-access", "phase": "exploit",
                  "desc": "Cuentas de dominio."},
    "T1078.003": {"name": "Local Accounts", "tactic": "initial-access", "phase": "exploit",
                  "desc": "Cuentas locales."},
    "T1189": {"name": "Drive-by Compromise", "tactic": "initial-access", "phase": "exploit",
              "desc": "Compromiso al visitar un sitio web."},
    "T1199": {"name": "Trusted Relationship", "tactic": "initial-access", "phase": "exploit",
              "desc": "Acceso a través de un tercero de confianza."},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "initial-access", "phase": "exploit",
              "desc": "Compromiso de la cadena de suministro."},
    "T1200": {"name": "Hardware Additions", "tactic": "initial-access", "phase": "exploit",
              "desc": "Introducir hardware no autorizado."},

    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "phase": "exploit",
              "desc": "Ejecutar comandos o scripts."},
    "T1059.001": {"name": "PowerShell", "tactic": "execution", "phase": "exploit",
                  "desc": "Ejecución mediante PowerShell."},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution", "phase": "exploit",
                  "desc": "Ejecución mediante shell Unix."},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "execution", "phase": "exploit",
              "desc": "Explotar un cliente (navegador, ofimática...)."},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "execution", "phase": "exploit",
              "desc": "Ejecución mediante WMI."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "execution", "phase": "exploit",
              "desc": "Ejecución programada."},
    "T1569": {"name": "System Services", "tactic": "execution", "phase": "exploit",
              "desc": "Ejecución mediante servicios del sistema."},
    "T1569.002": {"name": "Service Execution", "tactic": "execution", "phase": "exploit",
                  "desc": "Ejecución mediante servicios."},
    "T1610": {"name": "Deploy Container", "tactic": "execution", "phase": "exploit",
              "desc": "Desplegar un contenedor en el objetivo."},

    # Persistence
    "T1098": {"name": "Account Manipulation", "tactic": "persistence", "phase": "post",
              "desc": "Modificar cuentas para mantener acceso."},
    "T1136": {"name": "Create Account", "tactic": "persistence", "phase": "post",
              "desc": "Crear cuentas para persistir."},
    "T1543": {"name": "Create or Modify System Process", "tactic": "persistence", "phase": "post",
              "desc": "Crear o modificar servicios/procesos."},
    "T1543.002": {"name": "Systemd Service", "tactic": "persistence", "phase": "post",
                  "desc": "Persistencia mediante systemd."},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence", "phase": "post",
              "desc": "Persistencia al arrancar o iniciar sesión."},
    "T1505": {"name": "Server Software Component", "tactic": "persistence", "phase": "post",
              "desc": "Persistencia mediante componentes del servidor."},
    "T1505.003": {"name": "Web Shell", "tactic": "persistence", "phase": "post",
                  "desc": "Shell web para acceso persistente."},

    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation", "phase": "post",
              "desc": "Explotar una vulnerabilidad local para elevar privilegios."},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege-escalation", "phase": "post",
              "desc": "Abusar de mecanismos de elevación."},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "privilege-escalation", "phase": "post",
                  "desc": "Abusar de sudo o su caché."},
    "T1134": {"name": "Access Token Manipulation", "tactic": "privilege-escalation", "phase": "post",
              "desc": "Manipular tokens de acceso."},
    "T1055": {"name": "Process Injection", "tactic": "privilege-escalation", "phase": "post",
              "desc": "Inyectar código en procesos."},

    # Defense Evasion
    "T1562": {"name": "Impair Defenses", "tactic": "defense-evasion", "phase": "post",
              "desc": "Debilitar defensas."},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "defense-evasion", "phase": "post",
                  "desc": "Desactivar herramientas de seguridad."},
    "T1070": {"name": "Indicator Removal", "tactic": "defense-evasion", "phase": "post",
              "desc": "Eliminar indicadores."},
    "T1070.004": {"name": "File Deletion", "tactic": "defense-evasion", "phase": "post",
                  "desc": "Borrar ficheros."},
    "T1036": {"name": "Masquerading", "tactic": "defense-evasion", "phase": "post",
              "desc": "Suplantar nombres o rutas."},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion", "phase": "post",
              "desc": "Ofuscar contenido."},
    "T1222": {"name": "File and Directory Permissions Modification", "tactic": "defense-evasion", "phase": "post",
              "desc": "Modificar permisos."},

    # Credential Access
    "T1110": {"name": "Brute Force", "tactic": "credential-access", "phase": "exploit",
              "desc": "Fuerza bruta de credenciales."},
    "T1110.001": {"name": "Password Guessing", "tactic": "credential-access", "phase": "exploit",
                  "desc": "Adivinar contraseñas."},
    "T1110.002": {"name": "Password Cracking", "tactic": "credential-access", "phase": "exploit",
                  "desc": "Romper hashes de contraseñas."},
    "T1110.003": {"name": "Password Spraying", "tactic": "credential-access", "phase": "exploit",
                  "desc": "Probar contraseñas comunes contra muchas cuentas."},
    "T1110.004": {"name": "Credential Stuffing", "tactic": "credential-access", "phase": "exploit",
                  "desc": "Reutilizar credenciales filtradas."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access", "phase": "post",
              "desc": "Extraer credenciales del sistema operativo."},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential-access", "phase": "post",
                  "desc": "Volcar memoria de LSASS."},
    "T1003.002": {"name": "Security Account Manager", "tactic": "credential-access", "phase": "post",
                  "desc": "Extraer SAM."},
    "T1003.003": {"name": "NTDS", "tactic": "credential-access", "phase": "post",
                  "desc": "Extraer la base de datos NTDS."},
    "T1552": {"name": "Unsecured Credentials", "tactic": "credential-access", "phase": "post",
              "desc": "Credenciales en texto plano o mal protegidas."},
    "T1552.001": {"name": "Credentials In Files", "tactic": "credential-access", "phase": "post",
                  "desc": "Credenciales en ficheros."},
    "T1552.002": {"name": "Credentials in Registry", "tactic": "credential-access", "phase": "post",
                  "desc": "Credenciales en el registro."},
    "T1552.004": {"name": "Private Keys", "tactic": "credential-access", "phase": "post",
                  "desc": "Claves privadas expuestas."},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "credential-access", "phase": "post",
              "desc": "Credenciales de gestores."},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "credential-access", "phase": "exploit",
              "desc": "Interceptar comunicaciones."},
    "T1040": {"name": "Network Sniffing", "tactic": "credential-access", "phase": "exploit",
              "desc": "Capturar tráfico de red."},

    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir servicios de red."},
    "T1018": {"name": "Remote System Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir sistemas remotos."},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Obtener información del sistema."},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir ficheros y directorios."},
    "T1087": {"name": "Account Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir cuentas."},
    "T1087.001": {"name": "Local Account", "tactic": "discovery", "phase": "recon",
                  "desc": "Cuentas locales."},
    "T1087.002": {"name": "Domain Account", "tactic": "discovery", "phase": "recon",
                  "desc": "Cuentas de dominio."},
    "T1135": {"name": "Network Share Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir recursos compartidos."},
    "T1201": {"name": "Password Policy Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir la política de contraseñas."},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir grupos y permisos."},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir configuración de red."},
    "T1012": {"name": "Query Registry", "tactic": "discovery", "phase": "recon",
              "desc": "Consultar el registro."},
    "T1057": {"name": "Process Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir procesos."},
    "T1120": {"name": "Peripheral Device Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir periféricos."},
    "T1615": {"name": "Group Policy Discovery", "tactic": "discovery", "phase": "recon",
              "desc": "Descubrir políticas de grupo."},

    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement", "phase": "exploit",
              "desc": "Movimiento lateral mediante servicios remotos."},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral-movement", "phase": "exploit",
                  "desc": "Movimiento lateral por RDP."},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral-movement", "phase": "exploit",
                  "desc": "Movimiento lateral por SMB."},
    "T1021.004": {"name": "SSH", "tactic": "lateral-movement", "phase": "exploit",
                  "desc": "Movimiento lateral por SSH."},
    "T1021.005": {"name": "VNC", "tactic": "lateral-movement", "phase": "exploit",
                  "desc": "Movimiento lateral por VNC."},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "lateral-movement", "phase": "exploit",
                  "desc": "Movimiento lateral por WinRM."},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "lateral-movement", "phase": "exploit",
              "desc": "Explotar un servicio remoto."},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "lateral-movement", "phase": "post",
              "desc": "Transferir herramientas entre sistemas."},

    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "collection", "phase": "post",
              "desc": "Recoger datos locales."},
    "T1039": {"name": "Data from Network Shared Drive", "tactic": "collection", "phase": "post",
              "desc": "Recoger datos de recursos compartidos."},
    "T1074": {"name": "Data Staged", "tactic": "collection", "phase": "post",
              "desc": "Preparar datos para exfiltración."},
    "T1114": {"name": "Email Collection", "tactic": "collection", "phase": "post",
              "desc": "Recoger correo."},
    "T1119": {"name": "Automated Collection", "tactic": "collection", "phase": "post",
              "desc": "Recogida automatizada."},
    "T1560": {"name": "Archive Collected Data", "tactic": "collection", "phase": "post",
              "desc": "Archivar datos recogidos."},

    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control", "phase": "post",
              "desc": "C2 sobre protocolos de aplicación."},
    "T1071.001": {"name": "Web Protocols", "tactic": "command-and-control", "phase": "post",
                  "desc": "C2 sobre HTTP/HTTPS."},
    "T1071.004": {"name": "DNS", "tactic": "command-and-control", "phase": "post",
                  "desc": "C2 sobre DNS."},
    "T1571": {"name": "Non-Standard Port", "tactic": "command-and-control", "phase": "post",
              "desc": "C2 en puertos no estándar."},
    "T1573": {"name": "Encrypted Channel", "tactic": "command-and-control", "phase": "post",
              "desc": "Canal cifrado."},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "command-and-control", "phase": "post",
              "desc": "C2 en capas bajas."},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command-and-control", "phase": "post",
              "desc": "Descargar herramientas."},
    "T1090": {"name": "Proxy", "tactic": "command-and-control", "phase": "post",
              "desc": "Usar proxies."},
    "T1219": {"name": "Remote Access Software", "tactic": "command-and-control", "phase": "post",
              "desc": "Software de acceso remoto."},

    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration", "phase": "post",
              "desc": "Exfiltrar por el canal C2."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration", "phase": "post",
              "desc": "Exfiltrar por otro protocolo."},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration", "phase": "post",
              "desc": "Exfiltrar por servicios web."},
    "T1029": {"name": "Scheduled Transfer", "tactic": "exfiltration", "phase": "post",
              "desc": "Transferencias programadas."},
    "T1030": {"name": "Data Transfer Size Limits", "tactic": "exfiltration", "phase": "post",
              "desc": "Limitar el tamaño de transferencia."},

    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact", "phase": "post",
              "desc": "Cifrado de datos (ransomware)."},
    "T1489": {"name": "Service Stop", "tactic": "impact", "phase": "post",
              "desc": "Detener servicios."},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact", "phase": "post",
              "desc": "Impedir la recuperación."},
    "T1491": {"name": "Defacement", "tactic": "impact", "phase": "post",
              "desc": "Desfiguración."},
    "T1498": {"name": "Network Denial of Service", "tactic": "impact", "phase": "post",
              "desc": "Denegación de servicio."},
    "T1565": {"name": "Data Manipulation", "tactic": "impact", "phase": "post",
              "desc": "Manipulación de datos."},
    "T1531": {"name": "Account Access Removal", "tactic": "impact", "phase": "post",
              "desc": "Eliminar acceso a cuentas."},
}


TOOL_TECHNIQUES: dict[str, list[str]] = {
    "nmap": ["T1595", "T1595.001", "T1592.002", "T1046", "T1018"],
    "masscan": ["T1595", "T1595.001", "T1046"],
    "arp_scan": ["T1018", "T1590.004"],
    "http_probe": ["T1592.002", "T1594"],
    "whatweb": ["T1592.002", "T1594"],
    "nikto": ["T1595.002", "T1190"],
    "nuclei": ["T1595.002", "T1190"],
    "testssl": ["T1595.002", "T1557"],
    "ssh_audit": ["T1592.002", "T1021.004"],
    "smb": ["T1135", "T1087.002", "T1021.002"],
    "snmp": ["T1082", "T1016"],
    "dns": ["T1590", "T1590.004", "T1596"],
    "web_fuzz": ["T1083", "T1595.002"],
    "hydra": ["T1110", "T1110.001", "T1078"],
    "metasploit": ["T1190", "T1210", "T1203"],
    "searchsploit": ["T1596", "T1588.005"],
}


TAG_TECHNIQUES: dict[str, list[str]] = {
    "recon": ["T1595", "T1046"],
    "port-scan": ["T1595.001", "T1046"],
    "service-version": ["T1592.002"],
    "vuln-scan": ["T1595.002"],
    "exploit": ["T1190", "T1210"],
    "web": ["T1190", "T1594"],
    "tls": ["T1557"],
    "credentials": ["T1110", "T1078"],
    "brute-force": ["T1110", "T1110.001"],
    "valid-accounts": ["T1078"],
    "default-creds": ["T1078.001"],
    "smb": ["T1135", "T1021.002"],
    "rdp": ["T1021.001"],
    "ssh": ["T1021.004"],
    "vnc": ["T1021.005"],
    "winrm": ["T1021.006"],
    "snmp": ["T1082", "T1016"],
    "dns": ["T1590", "T1596"],
    "database": ["T1190", "T1210"],
    "docker": ["T1610"] if "T1610" in TECHNIQUES else ["T1190"],
    "kubernetes": ["T1190"],
    "misconfig": ["T1592.002"],
    "info-disclosure": ["T1592", "T1592.002"],
    "lateral": ["T1021", "T1210"],
    "discovery": ["T1046", "T1018"],
    "shares": ["T1135"],
    "users": ["T1087.002"],
}


TITLE_TECHNIQUES: list[tuple[str, list[str]]] = [
    ("smb", ["T1135", "T1021.002"]),
    ("samba", ["T1210", "T1021.002"]),
    ("rdp", ["T1021.001"]),
    ("escritorio remoto", ["T1021.001"]),
    ("ssh", ["T1021.004"]),
    ("vnc", ["T1021.005"]),
    ("winrm", ["T1021.006"]),
    ("telnet", ["T1021", "T1078"]),
    ("ftp", ["T1078", "T1552"]),
    ("snmp", ["T1082", "T1016"]),
    ("dns", ["T1590", "T1596"]),
    ("base de datos", ["T1190", "T1210"]),
    ("redis", ["T1190"]),
    ("mongodb", ["T1190"]),
    ("elasticsearch", ["T1190"]),
    ("docker", ["T1190"]),
    ("kubernetes", ["T1190"]),
    ("credencial", ["T1110", "T1078"]),
    ("contraseña", ["T1110", "T1078"]),
    ("exploit", ["T1190", "T1210"]),
    ("vulnerab", ["T1190", "T1210"]),
    ("certificado", ["T1557"]),
    ("tls", ["T1557"]),
    ("ssl", ["T1557"]),
    ("recon", ["T1595", "T1046"]),
    ("puerto", ["T1046"]),
    ("servicio", ["T1046", "T1592.002"]),
    ("directorio", ["T1083"]),
    ("recurso compartido", ["T1135"]),
    ("usuario", ["T1087"]),
]


KILL_CHAIN = [
    ("reconnaissance", "Reconocimiento", "Descubrimiento de hosts, puertos y servicios."),
    ("weaponization", "Armamento", "Selección de exploits y herramientas para los servicios vistos."),
    ("delivery", "Entrega", "Vectores de acceso disponibles (web, VPN, SMB, SSH...)."),
    ("exploitation", "Explotación", "Validación de vulnerabilidades y credenciales."),
    ("installation", "Instalación", "Persistencia. ROVSKA no la ejecuta; se marca como no evaluada."),
    ("command-and-control", "Mando y control", "Canales de salida. No evaluado sin agente."),
    ("actions", "Acciones sobre objetivos", "Movimiento lateral, recogida y exfiltración. No ejecutado."),
]


def _dedup(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in TECHNIQUES and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def techniques_for_finding(finding: Finding) -> list[str]:
    """Devuelve las técnicas ATT&CK asociadas a un hallazgo."""
    found: list[str] = list(finding.attack)
    for tag in finding.tags:
        found.extend(TAG_TECHNIQUES.get(tag.lower(), []))
    text = f"{finding.title} {finding.evidence}".lower()
    for keyword, ids in TITLE_TECHNIQUES:
        if keyword in text:
            found.extend(ids)
    if not found:
        source = (finding.source or "").lower()
        if source in TOOL_TECHNIQUES:
            found.extend(TOOL_TECHNIQUES[source])
        elif finding.severity in {"CRÍTICO", "ALTO"}:
            found.extend(["T1190", "T1210"])
        else:
            found.extend(["T1595", "T1046"])
    return _dedup(found)


def techniques_for_operation(tool: str) -> list[str]:
    return list(TOOL_TECHNIQUES.get(tool, []))


def build_matrix(findings: list[Finding], operations: list[dict] | None = None) -> dict:
    """Matriz ATT&CK agregada: tácticas -> técnicas con evidencias."""
    index: dict[str, dict] = {}
    for finding in findings:
        for tid in techniques_for_finding(finding):
            item = index.setdefault(
                tid,
                {
                    "id": tid,
                    "name": TECHNIQUES[tid]["name"],
                    "tactic": TECHNIQUES[tid]["tactic"],
                    "count": 0,
                    "hosts": [],
                    "max_severity": "INFO",
                    "sources": [],
                    "examples": [],
                },
            )
            item["count"] += 1
            if finding.host and finding.host not in item["hosts"]:
                item["hosts"].append(finding.host)
            if SEV_ORDER.index(finding.severity) < SEV_ORDER.index(item["max_severity"]):
                item["max_severity"] = finding.severity
            if finding.source and finding.source not in item["sources"]:
                item["sources"].append(finding.source)
            if len(item["examples"]) < 4:
                item["examples"].append(finding.title)

    for operation in operations or []:
        tool = operation.get("tool", "")
        for tid in techniques_for_operation(tool):
            item = index.setdefault(
                tid,
                {
                    "id": tid,
                    "name": TECHNIQUES[tid]["name"],
                    "tactic": TECHNIQUES[tid]["tactic"],
                    "count": 0,
                    "hosts": [],
                    "max_severity": "INFO",
                    "sources": [],
                    "examples": [],
                },
            )
            item["count"] += 1
            target = operation.get("target", "")
            if target and target not in item["hosts"]:
                item["hosts"].append(target)
            if tool not in item["sources"]:
                item["sources"].append(tool)
            if len(item["examples"]) < 4:
                item["examples"].append(f"Operación {tool}: {operation.get('kind', '')}")

    tactics = []
    for tactic_id, name, short in TACTICS:
        techniques = sorted(
            [t for t in index.values() if t["tactic"] == tactic_id],
            key=lambda t: (-t["count"], t["id"]),
        )
        tactics.append(
            {
                "id": tactic_id,
                "name": name,
                "short": short,
                "techniques": techniques,
                "count": sum(t["count"] for t in techniques),
                "techniques_count": len(techniques),
            }
        )
    return {
        "tactics": tactics,
        "techniques": sorted(index.values(), key=lambda t: t["id"]),
        "total": sum(t["count"] for t in index.values()),
        "unique": len(index),
    }


def coverage(tool_names: list[str]) -> dict:
    """Cobertura ATT&CK por herramienta disponible."""
    tools = {}
    for tool in tool_names:
        ids = TOOL_TECHNIQUES.get(tool, [])
        tools[tool] = {
            "techniques": ids,
            "names": [TECHNIQUES[i]["name"] for i in ids if i in TECHNIQUES],
        }
    covered = sorted({i for ids in TOOL_TECHNIQUES.values() for i in ids if i in TECHNIQUES})
    by_tactic = defaultdict(list)
    for tid in covered:
        by_tactic[TECHNIQUES[tid]["tactic"]].append(tid)
    return {
        "tools": tools,
        "covered": covered,
        "by_tactic": dict(by_tactic),
        "total_catalog": len(TECHNIQUES),
        "total_covered": len(covered),
    }


def build_kill_chain(
    hosts: list[Host],
    findings: list[Finding],
    operations: list[dict] | None = None,
) -> dict:
    """Reconstruye la cadena de ataque a partir de la evidencia disponible."""
    operations = operations or []
    steps_by_stage: dict[str, list[dict]] = {sid: [] for sid, _, _ in KILL_CHAIN}

    if hosts:
        open_ports = sum(len(h.ports) for h in hosts)
        steps_by_stage["reconnaissance"].append(
            {
                "technique": "T1595",
                "title": f"Descubrimiento de {len(hosts)} hosts y {open_ports} puertos",
                "host": "",
                "severity": "INFO",
                "evidence": ", ".join(h.ip for h in hosts[:12])
                + ("…" if len(hosts) > 12 else ""),
                "confidence": "alta",
            }
        )
    for finding in findings:
        text = f"{finding.title} {finding.evidence}".lower()
        ids = techniques_for_finding(finding)
        step = {
            "technique": ids[0] if ids else "",
            "title": finding.title,
            "host": finding.host,
            "severity": finding.severity,
            "evidence": finding.evidence,
            "confidence": finding.confidence,
        }
        if any(k in text for k in ("exploit", "vulnerab", "cve-", "backdoor", "rce")):
            steps_by_stage["exploitation"].append(step)
        if any(k in text for k in ("credencial", "contraseña", "password", "login", "brute")):
            steps_by_stage["exploitation"].append(step)
        if any(k in text for k in ("smb", "recurso compartido", "usuario", "snmp", "dns", "directorio")):
            steps_by_stage["reconnaissance"].append(step)
        if finding.severity in {"CRÍTICO", "ALTO"} and finding.host:
            # Un servicio expuesto es un vector potencial de acceso.
            steps_by_stage["delivery"].append(step)

    for operation in operations:
        tool = operation.get("tool", "")
        if tool in {"metasploit", "hydra"}:
            stage = "exploitation" if operation.get("status") in {"done", "running"} else "weaponization"
            steps_by_stage[stage].append(
                {
                    "technique": (techniques_for_operation(tool) or [""])[0],
                    "title": f"Operación {tool} ({operation.get('kind', '')})",
                    "host": operation.get("target", ""),
                    "severity": "INFO",
                    "evidence": f"estado {operation.get('status', '')} · dry_run={operation.get('dry_run')}",
                    "confidence": "alta" if operation.get("dry_run") == 0 else "media",
                }
            )
        else:
            steps_by_stage["weaponization"].append(
                {
                    "technique": (techniques_for_operation(tool) or [""])[0],
                    "title": f"Herramienta preparada: {tool}",
                    "host": operation.get("target", ""),
                    "severity": "INFO",
                    "evidence": operation.get("kind", ""),
                    "confidence": "alta",
                }
            )

    stages = []
    for stage_id, name, description in KILL_CHAIN:
        steps = steps_by_stage.get(stage_id, [])
        if steps:
            status = "observado"
        elif stage_id in {"installation", "command-and-control", "actions"}:
            status = "no evaluado"
        else:
            status = "sin evidencia"
        stages.append(
            {
                "id": stage_id,
                "name": name,
                "description": description,
                "status": status,
                "steps": steps[:20],
                "count": len(steps),
            }
        )
    return {
        "stages": stages,
        "observed": sum(1 for s in stages if s["status"] == "observado"),
        "total_steps": sum(s["count"] for s in stages),
    }


def summarize(findings: list[Finding]) -> dict:
    by_tactic: dict[str, int] = defaultdict(int)
    by_technique: dict[str, int] = defaultdict(int)
    for finding in findings:
        for tid in techniques_for_finding(finding):
            by_technique[tid] += 1
            by_tactic[TECHNIQUES[tid]["tactic"]] += 1
    return {
        "by_tactic": [
            {"id": tid, "name": name, "count": by_tactic.get(tid, 0)}
            for tid, name, _ in TACTICS
        ],
        "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
        "techniques": len(by_technique),
    }
