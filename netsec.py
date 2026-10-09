#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSIGhost - Módulo NETSEC
Herramientas de reconocimiento de infraestructura, detección de
exposición/filtraciones y auditoría local. Todo de sólo-lectura
(conexiones TCP normales, peticiones HTTP como las haría un navegador,
lectura de certificados). Nada de explotación, fuerza bruta de
credenciales, cracking ni payloads.

Dos tipos de funciones acá:

  - Librería reutilizada por RECON WEB (recon.py) para enriquecer sus
    sub-herramientas existentes: auditoría de protocolos/cifrados TLS,
    archivos sensibles expuestos y búsqueda de secretos en JS. Estas no
    imprimen su propio encabezado de sección: lo hace quien las llama,
    para que se vean como una sola herramienta y no como algo pegado.

  - Herramientas de primer nivel propias del menú principal: escaneo de
    puertos, descubrimiento de red local y auditoría local del sistema.
    Estas sí imprimen su propia sección.

Además vive acá el "logger" de reportes: envuelve la salida de cada
opción del menú para poder exportarla después como reporte para el
equipo de IT (opción REPORTE Y DIAGNÓSTICO).
"""

import csv
import datetime
import difflib
import getpass
import io
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

try:
    import psutil
except ImportError:
    psutil = None

from osighost import RED, WHITE, RESET, GREEN, YELLOW, CYAN, BOLD

USER_AGENT = {"User-Agent": "OSIGhost/1.0"}
TIMEOUT = 8


# ---------------------------------------------------------------------------
# Helpers de impresión (misma sintaxis que recon.py)
# ---------------------------------------------------------------------------
def _section(title):
    bar = "━" * max(40 - len(title), 4)
    print(f"\n{RED}━━━ {title} {bar}{RESET}\n")


def _ok(msg):
    print(f"{GREEN}[+]{RESET} {msg}")


def _info(msg):
    print(f"{CYAN}[*]{RESET} {msg}")


def _warn(msg):
    print(f"{YELLOW}[!]{RESET} {msg}")


def _err(msg):
    print(f"{RED}[-]{RESET} {msg}")


def _need(pip_name):
    _err(f"Falta el módulo '{pip_name}'. Instalá dependencias: pip install -r requirements.txt")


# ===========================================================================
# LIBRERÍA usada por RECON WEB (sin encabezado propio de sección)
# ===========================================================================

# ---------------------------------------------------------------------------
# A. Auditoría de protocolos TLS/SSL y cifrados débiles
#    (se suma dentro de la sub-herramienta "SSL / TLS" de Recon Web, que ya
#    muestra el certificado; esto agrega qué versiones/cifrados acepta)
# ---------------------------------------------------------------------------
PROTOCOLS_TO_TEST = []
for _name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
    _attr = f"PROTOCOL_{_name}"
    if hasattr(ssl, _attr):
        PROTOCOLS_TO_TEST.append((_name.replace("_", "."), getattr(ssl, _attr)))

WEAK_CIPHER_SUITES = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
OLD_PROTOCOLS = {"TLSv1", "TLSv1.1"}


def _try_protocol(host, port, proto_const):
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                s.getpeercert(binary_form=True)
        return True
    except Exception:
        return False


def _try_weak_ciphers(host, port):
    hits = []
    for suite in WEAK_CIPHER_SUITES:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(suite)
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    s.getpeercert(binary_form=True)
            hits.append(suite)
        except Exception:
            continue
    return hits


def audit_tls_protocols_and_ciphers(host, port=443):
    """Imprime qué versiones de TLS/SSL y qué cifrados débiles acepta el
    servidor. Pensada para llamarse DESPUÉS de mostrar el certificado,
    dentro de la misma sección 'TLS / SSL' de Recon Web."""
    print(f"\n{WHITE}Protocolos soportados{RESET}\n")
    any_old = False
    for label, const in PROTOCOLS_TO_TEST:
        ok = _try_protocol(host, port, const)
        if ok and label in OLD_PROTOCOLS:
            any_old = True
            print(f"   {RED}{label.ljust(10)} SOPORTADO (obsoleto/inseguro){RESET}")
        elif ok:
            print(f"   {GREEN}{label.ljust(10)} soportado{RESET}")
        else:
            print(f"   {CYAN}{label.ljust(10)} no soportado{RESET}")

    print(f"\n{WHITE}Cifrados débiles{RESET}\n")
    weak = _try_weak_ciphers(host, port)
    if weak:
        for w in weak:
            print(f"   {RED}{w.ljust(10)} ACEPTADO por el servidor{RESET}")
    else:
        print(f"   {GREEN}Ninguno de los probados fue aceptado{RESET}")

    if any_old or weak:
        _warn("Se detectaron configuraciones TLS obsoletas. Recomendar deshabilitarlas.")
    else:
        _ok("Configuración TLS razonable para lo probado.")


# ---------------------------------------------------------------------------
# B. Archivos sensibles expuestos (solo GET, igual que un navegador)
#    (se suma dentro de "Fuerza de Directorios": además del wordlist
#    genérico, prueba nombres puntuales de archivos de config/credenciales)
# ---------------------------------------------------------------------------
SENSITIVE_FILES = [
    ".env", ".env.bak", ".env.local", ".git/config", ".git/HEAD",
    ".svn/entries", ".DS_Store", ".htpasswd", ".htaccess",
    "web.config", "config.php.bak", "config.php.old", "wp-config.php.bak",
    "database.sql", "backup.sql", "db_backup.sql", "backup.zip", "backup.tar.gz",
    "docker-compose.yml", "Dockerfile", "composer.json", "composer.lock",
    "package.json", "package-lock.json", "id_rsa", "id_rsa.pub",
    ".aws/credentials", "phpinfo.php", "server-status", "actuator/env",
    "actuator/health", ".well-known/security.txt",
]

CRITICAL_SUFFIXES = (".env", "id_rsa", "credentials", ".sql", "config", "backup", ".bak", ".old")


def probe_sensitive_files(base_url, threads=20):
    """Prueba la lista SENSITIVE_FILES contra base_url. Devuelve solo los
    hits (status 200) como (path, status, length, es_critico); no imprime
    nada, lo hace quien llama (recon.mod_dirsearch)."""
    if requests is None:
        return []

    base = base_url.rstrip("/")

    def probe(path):
        try:
            r = requests.get(f"{base}/{path}", headers=USER_AGENT, verify=False,
                              timeout=TIMEOUT, allow_redirects=False)
            return path, r.status_code, len(r.content)
        except Exception:
            return path, None, None

    found = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for path, status, length in pool.map(probe, SENSITIVE_FILES):
            if status == 200 and length:
                critical = any(path.lower().endswith(s) or s in path.lower() for s in CRITICAL_SUFFIXES)
                found.append((path, status, length, critical))
    return found


# ---------------------------------------------------------------------------
# C. Secretos/API keys expuestas en páginas y JS públicos
#    (se suma dentro de "Crawler": a lo que ya encuentra de JS/links, le
#    agrega un escaneo de patrones de secretos sobre esos mismos archivos)
# ---------------------------------------------------------------------------
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Private Key": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----"),
    "Posible API Key genérica": re.compile(r"[\"']?[a-zA-Z0-9_]*api[_-]?key[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z\-_]{16,45}[\"']", re.I),
    "Posible Secret genérico": re.compile(r"[\"']?secret[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z\-_]{12,45}[\"']", re.I),
}


def _mask(value):
    if len(value) <= 8:
        return value[:2] + "…"
    return value[:4] + "…" + value[-4:]


def _scan_text_for_secrets(text, source):
    hits = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            hits.append((name, source, _mask(m.group(0))))
    return hits


def find_secrets_in_page_and_js(page_text, page_url, js_urls, max_js=30):
    """Busca patrones de secretos en el HTML ya descargado (page_text) y
    en hasta max_js archivos .js de js_urls. Devuelve (name, source,
    valor_enmascarado); no imprime nada, lo hace quien llama
    (recon.mod_crawler)."""
    hits = _scan_text_for_secrets(page_text, page_url)
    if requests is None or not js_urls:
        return hits

    targets = list(js_urls)[:max_js]

    def fetch_and_scan(js_url):
        try:
            r = requests.get(js_url, headers=USER_AGENT, verify=False, timeout=TIMEOUT)
            return _scan_text_for_secrets(r.text, js_url)
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=10) as pool:
        for found in pool.map(fetch_and_scan, targets):
            hits.extend(found)
    return hits


# ===========================================================================
# HERRAMIENTAS DE PRIMER NIVEL (imprimen su propia sección)
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. Escáner de puertos + banner grabbing (TCP connect scan)
# ---------------------------------------------------------------------------
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Sub", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    554: "RTSP (cámaras)", 8000: "HTTP-Alt", 8554: "RTSP-Alt",
}

# Puertos adicionales: solo para que el escaneo muestre un nombre de
# servicio en vez de "?" en la mayoría de los casos reales. No agregan
# ningún puerto nuevo a lo que YA se escaneaba por defecto más que estos
# mismos (antes también eran parte de "comunes" si el usuario los tipeaba
# a mano; ahora además se reconocen por nombre).
EXTRA_COMMON_PORTS = {
    20: "FTP-DATA", 69: "TFTP", 79: "Finger", 88: "Kerberos", 113: "Ident",
    119: "NNTP", 123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 194: "IRC", 389: "LDAP",
    427: "SLP", 464: "Kerberos-pass", 500: "IPSEC/ISAKMP", 512: "rexec",
    513: "rlogin", 514: "syslog/rsh", 515: "LPD", 520: "RIP", 548: "AFP",
    563: "NNTPS", 623: "IPMI", 631: "IPP/CUPS", 636: "LDAPS", 646: "LDP",
    860: "iSCSI", 873: "rsync", 902: "VMware", 903: "VMware", 912: "VMware",
    989: "FTPS-DATA", 990: "FTPS", 1025: "RPC-Alt", 1026: "RPC-Alt",
    1080: "SOCKS Proxy", 1194: "OpenVPN", 1414: "IBM-MQ", 1723: "PPTP",
    1883: "MQTT", 1900: "UPnP/SSDP", 2000: "Cisco SCCP", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 2095: "cPanel Webmail",
    2096: "cPanel Webmail-SSL", 2181: "Zookeeper", 2222: "SSH-Alt",
    2375: "Docker API", 2376: "Docker API-SSL", 2483: "Oracle DB",
    2484: "Oracle DB-SSL", 3000: "Dev Server (Node/Grafana)",
    3128: "Squid Proxy", 3260: "iSCSI Target", 3268: "AD Global Catalog",
    3269: "AD Global Catalog-SSL", 3307: "MySQL-Alt", 3690: "SVN",
    4040: "Spark UI", 4369: "Erlang Port Mapper", 4443: "HTTPS-Alt",
    4500: "IPSEC NAT-T", 4848: "GlassFish Admin", 4899: "Radmin",
    5000: "UPnP/Flask Dev", 5001: "HTTP-Alt", 5060: "SIP", 5061: "SIP-TLS",
    5222: "XMPP", 5269: "XMPP Server", 5351: "NAT-PMP", 5353: "mDNS",
    5355: "LLMNR", 5357: "WSDAPI", 5601: "Kibana", 5631: "pcAnywhere",
    5632: "pcAnywhere", 5672: "RabbitMQ", 5938: "TeamViewer", 5984: "CouchDB",
    6000: "X11", 6346: "Gnutella", 6443: "Kubernetes API", 6660: "IRC",
    6667: "IRC", 6881: "BitTorrent", 7000: "Cassandra", 7001: "Cassandra-SSL",
    7070: "RealServer", 7077: "Spark Master", 7199: "Cassandra JMX",
    7474: "Neo4j", 7547: "CWMP (TR-069)", 8008: "HTTP-Alt", 8009: "AJP",
    8020: "Hadoop NameNode", 8069: "Odoo", 8081: "HTTP-Alt",
    8086: "InfluxDB", 8088: "HTTP-Alt", 8089: "Splunk", 8090: "HTTP-Alt",
    8091: "Couchbase", 8111: "TeamCity", 8161: "ActiveMQ Admin",
    8181: "HTTP-Alt", 8200: "GoAnywhere/Consul", 8222: "HTTP-Alt",
    8291: "MikroTik Winbox", 8333: "Bitcoin", 8400: "HTTP-Alt",
    8444: "HTTPS-Alt", 8500: "Consul", 8530: "WSUS", 8531: "WSUS-SSL",
    8834: "Nessus", 8880: "HTTP-Alt", 8888: "HTTP-Alt", 8983: "Solr",
    9000: "PHP-FPM/SonarQube", 9001: "Tor ORPort", 9042: "Cassandra CQL",
    9043: "WebSphere Admin-SSL", 9050: "Tor SOCKS",
    9090: "Prometheus/WebSphere Admin", 9091: "HTTP-Alt", 9092: "Kafka",
    9099: "HTTP-Alt", 9100: "Impresora RAW", 9160: "Cassandra Thrift",
    9300: "Elasticsearch Transport", 9443: "HTTPS-Alt", 9999: "HTTP-Alt",
    10000: "Webmin", 10250: "Kubelet", 11211: "Memcached",
    15672: "RabbitMQ Mgmt", 16992: "Intel AMT", 16993: "Intel AMT-SSL",
    20000: "Usermin", 25565: "Minecraft", 27018: "MongoDB Shard",
    27019: "MongoDB Config", 28017: "MongoDB HTTP", 32400: "Plex",
    50000: "SAP", 50070: "Hadoop NameNode UI", 61616: "ActiveMQ",
}
COMMON_PORTS.update(EXTRA_COMMON_PORTS)


ALL_PORTS_KEYWORDS = ("all", "todos", "todo", "full", "*")


def _parse_ports(spec):
    """Acepta vacío (puertos comunes), 'todos'/'all' (1-65535), un rango
    '1-1024' o una lista mixta '22,80,443,8000-8100'. Lanza ValueError si
    la especificación no es válida."""
    spec = (spec or "").strip().lower()
    if not spec:
        return sorted(COMMON_PORTS)
    if spec in ALL_PORTS_KEYWORDS:
        return list(range(1, 65536))

    ports = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        try:
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                a, b = int(a), int(b)
                if a > b:
                    a, b = b, a
                ports.update(range(a, b + 1))
            else:
                ports.add(int(chunk))
        except ValueError:
            raise ValueError(f"'{chunk}' no es un puerto ni un rango válido")
    ports = sorted(p for p in ports if 0 < p < 65536)
    if not ports:
        raise ValueError("no quedó ningún puerto válido (el rango es 1-65535)")
    return ports


def _grab_banner(sock):
    try:
        sock.settimeout(1.5)
        data = sock.recv(128)
        return data.decode(errors="replace").strip().splitlines()[0][:80] if data else ""
    except Exception:
        return ""


def _scan_one(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = _grab_banner(s)
                return port, True, banner
    except Exception:
        pass
    return port, False, ""


def mod_portscan(host, port_spec="", threads=None, timeout=1.0):
    _section(f"Escaneo de Puertos ─ {host}")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return _err(f"No se pudo resolver el host : {exc}")

    try:
        ports = _parse_ports(port_spec)
    except ValueError as exc:
        return _err(f"Puertos inválidos : {exc}")

    total = len(ports)
    # Escaneos grandes (ej. los 65535 puertos) usan más hilos para no tardar una eternidad
    if threads is None:
        threads = 100 if total <= 2000 else 400

    es_total = total == 65535
    modo = "TODOS" if es_total else ("comunes" if not (port_spec or "").strip() else port_spec)
    _info(f"IP : {ip}  ·  {total} puertos ({modo})  ·  {threads} hilos")

    # Peor caso: el host descarta paquetes (filtrado) y cada intento agota el timeout
    peor_caso = (total / threads) * timeout
    if peor_caso > 20:
        _info(f"Tiempo estimado: hasta ~{peor_caso / 60:.1f} min si el host filtra paquetes "
              f"(mucho menos si responde rápido). Ctrl+C para cortar y ver lo encontrado.")

    open_ports = []
    done = 0
    interrumpido = False
    t0 = time.time()
    last_draw = 0.0

    pool = ThreadPoolExecutor(max_workers=threads)
    futs = []
    try:
        futs = [pool.submit(_scan_one, ip, p, timeout) for p in ports]
        for fut in as_completed(futs):
            done += 1
            now = time.time()
            if now - last_draw >= 0.15 or done == total:
                last_draw = now
                pct = done * 100 // total
                print(f"\r\033[K{CYAN}[*]{RESET} {done}/{total}  ({pct}%)", end="", flush=True)
            port, is_open, banner = fut.result()
            if is_open:
                open_ports.append((port, banner))
    except KeyboardInterrupt:
        interrumpido = True
        for f in futs:
            f.cancel()
    finally:
        pool.shutdown(wait=True)

    print("\r\033[K", end="")
    open_ports.sort()
    duracion = time.time() - t0

    if interrumpido:
        _warn(f"Escaneo interrumpido: resultados PARCIALES ({done}/{total} puertos analizados).")
    print(f"\n{GREEN}[+]{RESET} Puertos abiertos : {len(open_ports)}  "
          f"{CYAN}({done}/{total} analizados en {duracion:.1f}s){RESET}\n")
    for port, banner in open_ports:
        service = _service_name(port)
        line = f"   {GREEN}{str(port).ljust(6)}{RESET} {WHITE}{service.ljust(18)}{RESET}"
        if banner:
            line += f" {YELLOW}{banner}{RESET}"
        print(line)

    if not open_ports:
        _warn("Ningún puerto abierto en el rango analizado.")


# ---------------------------------------------------------------------------
# Helpers compartidos por los reportes detallados (LAN y Auditoría Local)
# ---------------------------------------------------------------------------
SEV_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]
SEV_COLOR = {"CRÍTICO": RED + BOLD, "ALTO": RED, "MEDIO": YELLOW, "BAJO": CYAN, "INFO": WHITE}

# Servicios que conviene revisar si están accesibles por red: (severidad, recomendación)
PORT_RISKS = {
    23:    ("CRÍTICO", "Telnet envía usuario y clave en texto plano. Deshabilitar y usar SSH."),
    21:    ("ALTO",    "FTP envía credenciales en texto plano. Migrar a SFTP/FTPS."),
    3389:  ("ALTO",    "RDP: verificar NLA, parches al día y que no sea alcanzable fuera de la red/VPN."),
    5900:  ("ALTO",    "VNC: autenticación débil y sin cifrado habitual. Restringir o usar VPN/túnel."),
    6379:  ("ALTO",    "Redis: sin autenticación por defecto. No exponer a la red."),
    27017: ("ALTO",    "MongoDB: verificar autenticación habilitada y acceso restringido por IP."),
    9200:  ("ALTO",    "Elasticsearch: verificar autenticación y que no sea accesible desde la red."),
    11211: ("ALTO",    "Memcached: sin autenticación. No exponer a la red."),
    445:   ("MEDIO",   "SMB: verificar que SMBv1 esté deshabilitado y los parches al día."),
    135:   ("MEDIO",   "MSRPC: limitar con firewall a lo estrictamente necesario."),
    139:   ("MEDIO",   "NetBIOS: deshabilitar si no se usa."),
    111:   ("MEDIO",   "RPC portmapper: deshabilitar si no se usa NFS/NIS."),
    2049:  ("MEDIO",   "NFS: verificar exportaciones restringidas por IP."),
    1433:  ("MEDIO",   "MSSQL accesible por red: restringir por firewall a los servidores que lo necesitan."),
    1521:  ("MEDIO",   "Oracle accesible por red: restringir por firewall a los servidores que lo necesitan."),
    3306:  ("MEDIO",   "MySQL accesible por red: restringir por firewall a los servidores que lo necesitan."),
    5432:  ("MEDIO",   "PostgreSQL accesible por red: restringir por firewall a los servidores que lo necesitan."),
    554:   ("MEDIO",   "RTSP (cámara/DVR): verificar que exija credenciales propias, no las de fábrica."),
    8554:  ("MEDIO",   "RTSP (cámara/DVR): verificar que exija credenciales propias, no las de fábrica."),
    9100:  ("BAJO",    "Impresora (RAW 9100) sin autenticación: limitar acceso / segmentar."),
    80:    ("BAJO",    "HTTP sin cifrar: si hay login o panel de administración, debería ir por HTTPS."),
    8080:  ("BAJO",    "HTTP alternativo sin cifrar: verificar qué expone y si requiere HTTPS."),
}


def _kv(label, value, width=18, indent="   "):
    print(f"{indent}{WHITE}{label.ljust(width)}{RESET}: {value}")


def _sub(title):
    print(f"\n{WHITE}❯ {title}{RESET}\n")


def _run_cmd(cmd, timeout=4):
    """Corre un comando y devuelve stdout+stderr como texto ('' si falla)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             errors="replace", timeout=timeout)
        return (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")
    except Exception:
        return ""


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _print_findings(findings):
    """findings: lista de (severidad, ámbito, mensaje)."""
    _sub("Resumen de hallazgos")
    if not findings:
        return _ok("Sin hallazgos relevantes en lo analizado.")

    counts = {s: 0 for s in SEV_ORDER}
    for sev, _, _ in findings:
        counts[sev] += 1
    resumen = "   ".join(f"{SEV_COLOR[s]}{s}: {counts[s]}{RESET}" for s in SEV_ORDER if counts[s])
    print(f"   {resumen}\n")

    for sev, scope, msg in sorted(findings, key=lambda f: (SEV_ORDER.index(f[0]), f[1])):
        tag = f"[{sev}]".ljust(10)
        print(f"   {SEV_COLOR[sev]}{tag}{RESET} {CYAN}{scope}{RESET} ─ {msg}")


def _is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _local_ips():
    """IPv4 propias de esta máquina (para marcar 'este equipo' en la LAN)."""
    ips = set()
    if psutil is not None:
        try:
            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    if a.family == socket.AF_INET:
                        ips.add(a.address)
        except Exception:
            pass
    try:  # truco UDP: no envía ningún paquete, solo consulta la ruta de salida
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    ips.discard("0.0.0.0")
    return ips


def _default_gateway():
    """Gateway por defecto (best-effort, devuelve None si no se puede saber)."""
    try:  # Linux / Android
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 3 and parts[1] == "00000000" and int(parts[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
    except Exception:
        pass

    if os.name == "nt":
        out = _run_cmd(["route", "print", "-4", "0.0.0.0"])
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None

    out = _run_cmd(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    out = _run_cmd(["netstat", "-rn"])
    m = re.search(r"^default\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# 2. Descubrimiento de red local (para auditar la LAN)
#    Reporte detallado por host: MAC/fabricante, latencia, TTL (SO estimado),
#    tipo de equipo estimado, puertos de servicios comunes con banner, y un
#    resumen de hallazgos de riesgo al final.
# ---------------------------------------------------------------------------
DISCOVERY_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 135: "MSRPC",
    139: "NetBIOS", 443: "HTTPS", 445: "SMB", 554: "RTSP", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-Alt", 9100: "Impresora RAW",
}
QUICK_ALIVE_PORTS = (80, 443, 22, 445, 3389)

# Prefijos MAC (OUI) de virtualización / placas conocidas. Lista corta a
# propósito: son los que sé con certeza; el resto aparece como "desconocido".
OUI_VENDORS = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "00:15:5d": "Microsoft Hyper-V",
    "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
}

_PING_TTL_RE = re.compile(r"ttl[=:\s]*(\d+)", re.I)
_PING_TIME_RE = re.compile(r"(?:time|tiempo)\s*([=<])\s*([\d.,]+)", re.I)
_ARP_LINE_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\b.*?([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})", re.I)


def _ping_info(host, timeout=1.0):
    """Ping cross-platform vía subprocess (no requiere sockets raw/root).
    Devuelve dict con alive, ttl y rtt (ms)."""
    is_windows = platform.system().lower().startswith("win")
    cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host] if is_windows \
        else ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), host]
    vacio = {"alive": False, "ttl": None, "rtt": None}
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                             timeout=timeout + 2)
    except Exception:
        return vacio

    out = res.stdout or ""
    m_ttl = _PING_TTL_RE.search(out)
    ttl = int(m_ttl.group(1)) if m_ttl else None
    # En Windows el exit code puede ser 0 aun con "host inaccesible": exigimos TTL
    alive = res.returncode == 0 and (ttl is not None or not is_windows)
    if not alive:
        return vacio

    rtt = None
    m_t = _PING_TIME_RE.search(out)
    if m_t:
        try:
            rtt = 1.0 if m_t.group(1) == "<" else float(m_t.group(2).replace(",", "."))
        except ValueError:
            rtt = None
    return {"alive": True, "ttl": ttl, "rtt": rtt}


def _tcp_open(host, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _quick_tcp_alive(host, ports=QUICK_ALIVE_PORTS, timeout=0.6):
    return any(_tcp_open(host, p, timeout) for p in ports)


def _read_arp_table():
    """Tabla ARP/vecinos del sistema → {ip: mac}. Solo hay MAC de equipos de
    la misma red local (mismo segmento) con los que ya hubo tráfico."""
    texts = []
    try:
        with open("/proc/net/arp") as f:
            texts.append(f.read())
    except Exception:
        pass
    texts.append(_run_cmd(["ip", "neigh"]))
    texts.append(_run_cmd(["arp", "-a"] if os.name == "nt" else ["arp", "-an"]))

    table = {}
    for text in texts:
        for line in text.splitlines():
            m = _ARP_LINE_RE.match(line)
            if not m:
                continue
            mac = m.group(2).lower().replace("-", ":")
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue
            table.setdefault(m.group(1), mac)
    return table


def _mac_details(mac):
    """(fabricante_o_None, es_aleatoria). Una MAC con el bit 'administrada
    localmente' activo suele ser celular con MAC privada, VM o contenedor."""
    if not mac:
        return None, False
    vendor = OUI_VENDORS.get(mac[:8])
    try:
        randomized = bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        randomized = False
    return vendor, randomized


def _guess_os(ttl):
    """Estimación por TTL inicial (64/128/255). Es orientativa, no exacta."""
    if ttl is None:
        return "No determinado"
    if ttl <= 64:
        return f"Linux / Unix / macOS / Android / iOS  (TTL {ttl})"
    if ttl <= 128:
        return f"Windows  (TTL {ttl})"
    return f"Equipo de red (router/switch) u otro  (TTL {ttl})"


def _device_hint(ports, ttl, is_gateway):
    p = set(ports)
    hints = []
    if is_gateway:
        hints.append("Gateway / router de la red")
    if p & {554, 8554}:
        hints.append("Cámara IP / DVR / NVR")
    if 9100 in p:
        hints.append("Impresora de red")
    if p & {3389, 135}:
        hints.append("Equipo Windows")
    elif p & {139, 445}:
        if ttl is not None and ttl <= 64:
            hints.append("Servidor de archivos SMB (Samba / NAS) o equipo Unix")
        else:
            hints.append("Equipo Windows")
    elif 22 in p and ttl is not None and ttl <= 64:
        hints.append("Servidor / equipo Linux-Unix")
    if not hints and p and p <= {53, 80, 443, 8080}:
        hints.append("Equipo con panel web (router / AP / IoT / servidor web)")
    return " · ".join(hints) if hints else "No determinado"


def mod_netdiscover(cidr, threads=50):
    _section(f"Descubrimiento de Red ─ {cidr}")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return _err(f"Rango inválido : {exc}")

    hosts = list(net.hosts())
    if len(hosts) > 1024:
        return _warn(f"Rango demasiado grande ({len(hosts)} hosts). Usá un /24 o más chico.")

    own_ips = {ip for ip in _local_ips() if ipaddress.ip_address(ip) in net}
    gateway = _default_gateway()
    gateway = gateway if gateway and ipaddress.ip_address(gateway) in net else None

    _sub("Datos del relevamiento")
    _kv("Red", f"{net.network_address}/{net.prefixlen}  (máscara {net.netmask})")
    _kv("Hosts a analizar", f"{len(hosts)}  ·  {threads} hilos")
    _kv("Fecha / hora", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _kv("Este equipo", ", ".join(sorted(own_ips)) if own_ips else "no está dentro de este rango")
    _kv("Gateway", gateway or "no detectado en este rango")
    _kv("Puertos revisados", ", ".join(str(p) for p in DISCOVERY_PORTS))

    def probe(ip_obj):
        ip = str(ip_obj)
        ping = _ping_info(ip)
        via = []
        if ping["alive"]:
            via.append("ICMP")
        elif _quick_tcp_alive(ip):
            via.append("TCP")        # no responde ping (firewall) pero sí por TCP
        else:
            return None

        open_ports = []
        for port in DISCOVERY_PORTS:
            p, is_open, banner = _scan_one(ip, port, 0.5)
            if is_open:
                open_ports.append((p, banner))
        if open_ports and "TCP" not in via:
            via.append("TCP")

        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        return {"ip": ip, "name": name, "via": via, "ttl": ping["ttl"],
                "rtt": ping["rtt"], "ports": sorted(open_ports)}

    t0 = time.time()
    print()
    found = []
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for res in pool.map(probe, hosts):
            done += 1
            print(f"\r\033[K{CYAN}[*]{RESET} {done}/{len(hosts)}", end="", flush=True)
            if res:
                found.append(res)
    print("\r\033[K", end="")
    duracion = time.time() - t0

    found.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    arp = _read_arp_table()           # se lee DESPUÉS del barrido: ya está poblada

    # --- Detalle por host --------------------------------------------------
    _sub(f"Hosts activos : {len(found)} de {len(hosts)}  ·  barrido en {duracion:.1f}s")
    findings = []
    n_riesgo = n_mac = n_name = 0

    for h in found:
        ip = h["ip"]
        mac = arp.get(ip)
        vendor, randomized = _mac_details(mac)
        is_gw = ip == gateway
        etiquetas = []
        if ip in own_ips:
            etiquetas.append("ESTE EQUIPO")
        if is_gw:
            etiquetas.append("GATEWAY")
        tag = f"  {YELLOW}◄ {' · '.join(etiquetas)}{RESET}" if etiquetas else ""

        print(f"{GREEN}┌─ {ip}{RESET}{tag}")
        _kv("Nombre (DNS inv.)", h["name"] or f"{CYAN}sin registro{RESET}", indent="│  ")
        if mac:
            extra = f"  {CYAN}({vendor}){RESET}" if vendor else ""
            if randomized and not vendor:
                extra = f"  {CYAN}(MAC administrada localmente: típico de celular con MAC privada, VM o contenedor){RESET}"
            _kv("MAC", f"{mac}{extra}", indent="│  ")
            n_mac += 1
        else:
            _kv("MAC", f"{CYAN}no disponible (otro segmento o sin entrada ARP){RESET}", indent="│  ")

        rtt = (f"{h['rtt']:.2f} ms" if h["rtt"] < 10 else f"{h['rtt']:.1f} ms") if h["rtt"] is not None else "n/d"
        _kv("Detectado por", f"{' + '.join(h['via'])}  ·  latencia {rtt}", indent="│  ")
        _kv("SO (estimado)", _guess_os(h["ttl"]), indent="│  ")
        _kv("Tipo (estimado)", _device_hint([p for p, _ in h["ports"]], h["ttl"], is_gw), indent="│  ")

        if h["ports"]:
            print(f"│  {WHITE}{'Puertos abiertos'.ljust(18)}{RESET}:")
            for port, banner in h["ports"]:
                svc = DISCOVERY_PORTS.get(port) or _service_name(port)
                sev = PORT_RISKS.get(port, (None,))[0]
                color = SEV_COLOR.get(sev, GREEN) if sev in ("CRÍTICO", "ALTO", "MEDIO") else GREEN
                line = f"│     {color}{str(port).ljust(6)}{RESET} {WHITE}{svc.ljust(14)}{RESET}"
                if banner:
                    line += f" {YELLOW}{banner}{RESET}"
                print(line)
                if port in PORT_RISKS:
                    findings.append((PORT_RISKS[port][0], ip,
                                     f"{port}/{svc} abierto ─ {PORT_RISKS[port][1]}"))
        else:
            _kv("Puertos abiertos", f"{CYAN}ninguno de los revisados{RESET}", indent="│  ")
        print("└─\n")

        if h["name"]:
            n_name += 1
        if any(p in PORT_RISKS and PORT_RISKS[p][0] in ("CRÍTICO", "ALTO", "MEDIO") for p, _ in h["ports"]):
            n_riesgo += 1

    if not found:
        _warn("No se encontró ningún host activo en el rango.")
        return

    # --- Estadísticas + hallazgos -------------------------------------------
    _sub("Estadísticas")
    _kv("Hosts activos", f"{len(found)} de {len(hosts)}  ({len(found) * 100 // len(hosts)}% del rango)", width=26)
    _kv("Con nombre DNS", f"{n_name}", width=26)
    _kv("Con MAC conocida", f"{n_mac}", width=26)
    _kv("Con servicios a revisar", f"{n_riesgo}  (severidad MEDIO o superior)", width=26)
    _kv("Sin respuesta a ping", f"{sum(1 for h in found if 'ICMP' not in h['via'])}  (probable firewall en el equipo)", width=26)

    _print_findings(findings)
    print(f"\n{CYAN}[*]{RESET} SO y tipo de equipo son ESTIMACIONES (TTL y puertos): confirmalos con el inventario real.")


# ---------------------------------------------------------------------------
# 2.5 Auditoría de Host remoto (IP o dominio que el usuario pasa como
#     objetivo). A diferencia de la Auditoría Local (más abajo), esta NO
#     corre en la máquina de OSIGhost: todo lo que mide son cosas que se
#     pueden observar desde afuera por red (ping/TTL, puertos abiertos +
#     banner, riesgo por servicio, y TLS/cifrados si hay 443/8443 abierto).
#     Pensada para auditar un servidor/activo de un cliente sin acceso
#     local a esa máquina.
# ---------------------------------------------------------------------------
def _http_quick_check(host, port):
    """Chequeo liviano del servidor web en host:port: header Server,
    X-Powered-By, redirecciones y si faltan headers de seguridad básicos.
    (El detalle completo de headers ya lo cubre la herramienta "Headers
    HTTP" de Recon Web; esto es solo un vistazo rápido dentro de la
    auditoría del host.)"""
    if requests is None:
        return _need("requests")
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    try:
        r = requests.get(url, headers=USER_AGENT, verify=False, timeout=TIMEOUT)
    except Exception as exc:
        return _warn(f"No se pudo conectar por HTTP(S) : {exc}")

    _kv("URL", r.url)
    _kv("Status final", f"{r.status_code}" + (f"  (tras {len(r.history)} redirección/es)" if r.history else ""))
    _kv("Server", r.headers.get("Server", "no informado"))
    if r.headers.get("X-Powered-By"):
        _kv("X-Powered-By", r.headers["X-Powered-By"])

    faltantes = [h for h in ("Strict-Transport-Security", "X-Content-Type-Options",
                              "X-Frame-Options", "Content-Security-Policy")
                 if h not in r.headers]
    if faltantes:
        _kv("Headers de seguridad faltantes", ", ".join(faltantes))
    else:
        _kv("Headers de seguridad básicos", f"{GREEN}presentes{RESET}")
    return faltantes


def mod_hostaudit(host, threads=150, timeout=1.0):
    _section(f"Auditoría de Host ─ {host}")
    t0 = time.time()

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return _err(f"No se pudo resolver el host : {exc}")

    findings = []

    _sub("Datos del objetivo")
    _kv("Host", host)
    if ip != host:
        _kv("IP", ip)
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        ptr = None
    _kv("DNS inverso (PTR)", ptr or f"{CYAN}sin registro{RESET}")
    _kv("Fecha / hora", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    ping = _ping_info(ip)
    if ping["alive"]:
        rtt = f"{ping['rtt']:.1f} ms" if ping["rtt"] is not None else "n/d"
        _kv("Ping (ICMP)", f"{GREEN}responde{RESET}  ·  latencia {rtt}")
        _kv("SO (estimado por TTL)", _guess_os(ping["ttl"]))
    else:
        _kv("Ping (ICMP)", f"{CYAN}sin respuesta{RESET}  (puede filtrar ICMP, no implica que esté caído)")

    ports = sorted(COMMON_PORTS)
    _sub(f"Escaneo de puertos relevantes ({len(ports)} puertos comunes/de riesgo)")
    open_ports = []
    done = 0
    pool = ThreadPoolExecutor(max_workers=threads)
    try:
        futs = [pool.submit(_scan_one, ip, p, timeout) for p in ports]
        for fut in as_completed(futs):
            done += 1
            print(f"\r\033[K{CYAN}[*]{RESET} {done}/{len(ports)}", end="", flush=True)
            port, is_open, banner = fut.result()
            if is_open:
                open_ports.append((port, banner))
    except KeyboardInterrupt:
        _warn("Escaneo interrumpido: resultados parciales.")
        for f in futs:
            f.cancel()
    finally:
        pool.shutdown(wait=True)
    print("\r\033[K", end="")
    open_ports.sort()

    if open_ports:
        print(f"\n{GREEN}[+]{RESET} Puertos abiertos : {len(open_ports)}\n")
        for port, banner in open_ports:
            svc = _service_name(port)
            riesgo = PORT_RISKS.get(port)
            sev = riesgo[0] if riesgo else None
            color = SEV_COLOR.get(sev, GREEN) if sev else GREEN
            line = f"   {color}{str(port).ljust(6)}{RESET} {WHITE}{svc.ljust(26)}{RESET}"
            if banner:
                line += f" {YELLOW}{banner}{RESET}"
            print(line)
            if riesgo:
                findings.append((riesgo[0], f"{host}:{port}", f"{svc} abierto ─ {riesgo[1]}"))
    else:
        _warn("Ningún puerto de la lista revisada está abierto (o todos filtrados).")

    abiertos = {p for p, _ in open_ports}

    for port in (80, 8080, 8000, 8008, 8081, 8090):
        if port in abiertos:
            _sub(f"Servidor web (HTTP) ─ puerto {port}")
            faltantes = _http_quick_check(host, port)
            if faltantes:
                findings.append(("BAJO", f"{host}:{port}",
                                  f"Faltan headers de seguridad: {', '.join(faltantes)}"))

    for port in (443, 8443):
        if port in abiertos:
            _sub(f"TLS / SSL ─ puerto {port}")
            try:
                audit_tls_protocols_and_ciphers(host, port)
            except Exception as exc:
                _warn(f"No se pudo completar la auditoría TLS en el puerto {port} : {exc}")
            faltantes = _http_quick_check(host, port)
            if faltantes:
                findings.append(("BAJO", f"{host}:{port}",
                                  f"Faltan headers de seguridad: {', '.join(faltantes)}"))

    _print_findings(findings)
    print(f"\n{CYAN}[*]{RESET} Auditoría completada en {time.time() - t0:.1f}s"
          f"  ·  SO y servicios son estimaciones, confirmalos manualmente.")


# ---------------------------------------------------------------------------
# 3. Auditoría local (la máquina donde corre OSIGhost: estación/servidor interno)
#    Reporte detallado: sistema, recursos, discos, interfaces, gateway/DNS,
#    firewall, puertos en escucha (TCP/UDP) con proceso y alcance, conexiones
#    establecidas, sesiones, procesos y resumen de hallazgos.
#    (Esta SÍ es necesariamente local: procesos, discos y sesiones de una
#    IP remota no se pueden leer por red sin un agente instalado ahí. Para
#    auditar una IP/dominio de un cliente se usa "Auditoría de Host" de
#    arriba.)
# ---------------------------------------------------------------------------
EXPOSED_BINDS = ("0.0.0.0", "::")
LOOPBACK_BINDS = ("127.0.0.1", "::1")


def _dns_servers():
    servers = []
    if os.name == "nt":
        capturando = False
        for line in _run_cmd(["ipconfig", "/all"], timeout=8).splitlines():
            if "DNS" in line and ":" in line:
                capturando = True
                servers += re.findall(r"\d+\.\d+\.\d+\.\d+", line)
            elif capturando and re.fullmatch(r"\s+\d+\.\d+\.\d+\.\d+\s*", line):
                servers.append(line.strip())
            else:
                capturando = False
    else:
        try:
            with open("/etc/resolv.conf") as f:
                servers = re.findall(r"^\s*nameserver\s+(\S+)", f.read(), re.M)
        except Exception:
            pass
    vistos = []
    for s in servers:
        if s not in vistos:
            vistos.append(s)
    return vistos


def _firewall_status():
    """Devuelve (estado, detalle). estado ∈ {'activo','inactivo','parcial','desconocido'}."""
    sistema = platform.system().lower()

    if sistema.startswith("win"):
        out = _run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=8)
        estados = []
        for line in out.splitlines():
            if re.search(r"\b(state|estado)\b", line, re.I):
                estados.append(bool(re.search(r"\b(ON|ACTIVADO|ACTIVO)\b", line, re.I)))
        if estados:
            if all(estados):
                return "activo", f"Firewall de Windows ACTIVO en {len(estados)} perfiles"
            if not any(estados):
                return "inactivo", "Firewall de Windows DESACTIVADO en todos los perfiles"
            return "parcial", f"Activo en {sum(estados)} de {len(estados)} perfiles de Windows"
        return "desconocido", "No se pudo leer el estado (probá como administrador)"

    if sistema == "darwin":
        out = _run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if re.search(r"enabled|State = [12]", out, re.I):
            return "activo", "Firewall de aplicaciones de macOS habilitado"
        if re.search(r"disabled|State = 0", out, re.I):
            return "inactivo", "Firewall de aplicaciones de macOS deshabilitado"
        return "desconocido", "No se pudo leer el estado"

    # Linux / Termux
    out = _run_cmd(["ufw", "status"])
    if re.search(r"status:\s*active", out, re.I):
        return "activo", "UFW activo"
    if re.search(r"status:\s*inactive", out, re.I):
        return "inactivo", "UFW instalado pero INACTIVO"
    out = _run_cmd(["firewall-cmd", "--state"])
    if "running" in out and "not running" not in out:
        return "activo", "firewalld en ejecución"
    try:
        with open("/etc/ufw/ufw.conf") as f:
            if re.search(r"^ENABLED=yes", f.read(), re.M | re.I):
                return "activo", "UFW habilitado (según /etc/ufw/ufw.conf)"
            return "inactivo", "UFW instalado pero deshabilitado (según /etc/ufw/ufw.conf)"
    except Exception:
        pass
    return "desconocido", "No se pudo determinar (ufw/firewalld/iptables suelen requerir root)"


def _proc_info(pid):
    """(nombre, usuario, ruta) del proceso; '-' si no hay permisos."""
    if not pid:
        return "-", "-", "-"
    try:
        p = psutil.Process(pid)
        name = p.name()
        try:
            user = p.username()
        except Exception:
            user = "-"
        try:
            exe = p.exe() or "-"
        except Exception:
            exe = "-"
        return name, user, exe
    except Exception:
        return "?", "-", "-"


def _service_name(port):
    """Nombre de servicio para un puerto: primero la tabla propia de
    OSIGhost (más completa y pensada para seguridad), y si no está ahí,
    se le pregunta al sistema operativo (/etc/services). Solo si ninguna
    de las dos lo conoce se muestra 'desconocido' en vez de '?'."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        pass
    try:
        return socket.getservbyport(port)
    except Exception:
        return "desconocido"


def _audit_sistema(findings):
    _sub("Sistema")
    _kv("Sistema operativo", platform.platform())
    _kv("Arquitectura", platform.machine() or "-")
    _kv("Hostname", socket.gethostname())
    _kv("FQDN", socket.getfqdn())
    try:
        _kv("Usuario actual", getpass.getuser())
    except Exception:
        pass
    admin = _is_admin()
    _kv("Privilegios", f"{GREEN}administrador/root{RESET}" if admin
        else f"{YELLOW}usuario común{RESET}  (algunos procesos/puertos pueden no mostrarse)")
    _kv("Python", platform.python_version())

    boot = datetime.datetime.fromtimestamp(psutil.boot_time())
    up = datetime.datetime.now() - boot
    _kv("Último reinicio", f"{boot:%Y-%m-%d %H:%M}  (hace {up.days}d {up.seconds // 3600}h)")
    if up.days > 90:
        findings.append(("BAJO", "local", f"Sin reiniciar hace {up.days} días: posibles actualizaciones pendientes de aplicar."))

    _sub("Recursos")
    _kv("CPU", f"{psutil.cpu_count(logical=True)} núcleos lógicos  ·  uso {psutil.cpu_percent(interval=0.5):.0f}%")
    vm = psutil.virtual_memory()
    _kv("Memoria RAM", f"{_fmt_bytes(vm.used)} de {_fmt_bytes(vm.total)}  ({vm.percent:.0f}%)")
    if vm.percent >= 90:
        findings.append(("MEDIO", "local", f"Uso de RAM muy alto ({vm.percent:.0f}%)."))


def _audit_discos(findings):
    _sub("Discos")
    mostrados = 0
    for part in psutil.disk_partitions(all=False):
        if not part.fstype or "cdrom" in part.opts or part.device.startswith("/dev/loop"):
            continue
        # Imágenes de solo lectura (squashfs/snap, ISO) siempre están "al 100%": no son un riesgo
        if part.fstype in ("squashfs", "iso9660", "udf") or "ro" in part.opts.split(","):
            continue
        try:
            u = psutil.disk_usage(part.mountpoint)
        except Exception:
            continue
        mostrados += 1
        color = RED if u.percent >= 90 else (YELLOW if u.percent >= 80 else GREEN)
        print(f"   {WHITE}{part.mountpoint.ljust(18)}{RESET} {part.fstype.ljust(8)} "
              f"{color}{u.percent:5.1f}%{RESET}  {_fmt_bytes(u.used)} de {_fmt_bytes(u.total)}")
        if u.percent >= 90:
            findings.append(("MEDIO", part.mountpoint, f"Disco casi lleno ({u.percent:.0f}%): riesgo para logs, backups y estabilidad."))
    if not mostrados:
        _info("Sin datos de discos.")


def _audit_red(findings):
    _sub("Interfaces de red")
    addrs_all = psutil.net_if_addrs()
    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}

    for iface, addrs in addrs_all.items():
        st = stats.get(iface)
        estado = f"{GREEN}UP{RESET}" if (st and st.isup) else f"{CYAN}DOWN{RESET}"
        vel = f"  ·  {st.speed} Mbps" if st and st.speed else ""
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), "")
        print(f"   {CYAN}{iface}{RESET}  [{estado}]{vel}" + (f"  ·  MAC {mac}" if mac else ""))
        for a in addrs:
            if a.family == socket.AF_INET:
                mask = f"/{a.netmask}" if a.netmask else ""
                print(f"        IPv4  {a.address}{mask}")
                try:
                    if ipaddress.ip_address(a.address).is_global:
                        findings.append(("MEDIO", iface, f"IP pública directa ({a.address}): verificar firewall y servicios expuestos."))
                except ValueError:
                    pass
            elif a.family == socket.AF_INET6:
                print(f"        IPv6  {a.address.split('%')[0]}")

    _sub("Gateway y DNS")
    gw = _default_gateway()
    _kv("Gateway", gw or f"{CYAN}no detectado{RESET}")
    dns = _dns_servers()
    _kv("Servidores DNS", ", ".join(dns) if dns else f"{CYAN}no detectados{RESET}")


def _audit_firewall(findings):
    _sub("Firewall del equipo")
    estado, detalle = _firewall_status()
    color = {"activo": GREEN, "inactivo": RED, "parcial": YELLOW}.get(estado, CYAN)
    print(f"   {color}{estado.upper()}{RESET} ─ {detalle}")
    if estado == "inactivo":
        findings.append(("ALTO", "local", "Firewall del equipo desactivado: todos los servicios en escucha quedan accesibles desde la red."))
    elif estado == "parcial":
        findings.append(("MEDIO", "local", detalle))
    elif estado == "desconocido":
        findings.append(("INFO", "local", "No se pudo verificar el firewall (ejecutar como admin/root para confirmarlo)."))


def _get_connections():
    try:
        return psutil.net_connections(kind="inet"), True
    except (PermissionError, psutil.AccessDenied):
        return [], False


def _audit_puertos(conns, permiso, findings):
    _sub("Puertos en escucha")
    if not permiso:
        _warn("Se requieren más permisos para ver las conexiones (probá como admin/root).")
        findings.append(("INFO", "local", "No se pudieron listar puertos/conexiones por falta de permisos."))
        return

    # Agrupa por (protocolo, puerto, pid, alcance) juntando IPv4/IPv6
    grupos = {}
    for c in conns:
        if not c.laddr:
            continue
        if c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN:
            proto = "TCP"
        elif c.type == socket.SOCK_DGRAM and not c.raddr:
            proto = "UDP"
        else:
            continue
        ip = c.laddr.ip
        alcance = "EXPUESTO" if ip in EXPOSED_BINDS else ("LOCAL" if ip in LOOPBACK_BINDS else "IFACE")
        g = grupos.setdefault((proto, c.laddr.port, c.pid, alcance), set())
        g.add(ip)

    if not grupos:
        return _info("No hay puertos en escucha (o no se pudieron leer).")

    orden = {"EXPUESTO": 0, "IFACE": 1, "LOCAL": 2}
    filas = sorted(grupos.items(), key=lambda kv: (orden[kv[0][3]], kv[0][0], kv[0][1]))

    print(f"   {WHITE}{'PROTO'.ljust(6)}{'PUERTO'.ljust(8)}{'ALCANCE'.ljust(10)}{'SERVICIO'.ljust(14)}PROCESO{RESET}")
    exp_tcp = 0
    for (proto, port, pid, alcance), ips in filas:
        name, user, exe = _proc_info(pid)
        svc = _service_name(port)
        riesgo = PORT_RISKS.get(port) if (proto == "TCP" and alcance != "LOCAL") else None

        if alcance == "LOCAL":
            col = GREEN
        elif riesgo and riesgo[0] in ("CRÍTICO", "ALTO"):
            col = RED
        else:
            col = YELLOW if alcance == "EXPUESTO" else WHITE
        if proto == "TCP" and alcance == "EXPUESTO":
            exp_tcp += 1

        if pid:
            proc = f"{CYAN}{name}{RESET} (pid {pid}) · {user}"
        else:
            proc = f"{CYAN}proceso no visible{RESET} (probá como admin/root)"
        print(f"   {WHITE}{proto.ljust(6)}{RESET}{col}{str(port).ljust(8)}{alcance.ljust(10)}{RESET}"
              f"{svc.ljust(14)}{proc}")
        print(f"   {' ' * 6}{CYAN}bind: {', '.join(sorted(ips))}"
              + (f"  ·  ruta: {exe}" if alcance != "LOCAL" and exe != "-" else "") + f"{RESET}")

        if riesgo:
            findings.append((riesgo[0], f"{proto}/{port}",
                             f"{svc} en escucha ({alcance.lower()}) por {name} ─ {riesgo[1]}"))

    total_tcp = sum(1 for k in grupos if k[0] == "TCP")
    total_udp = len(grupos) - total_tcp
    print(f"\n   {WHITE}Total{RESET}: {total_tcp} TCP · {total_udp} UDP  ·  "
          f"{YELLOW}{exp_tcp} TCP expuestos a toda la red{RESET}")
    if exp_tcp > 15:
        findings.append(("BAJO", "local", f"{exp_tcp} puertos TCP expuestos a toda la red: conviene reducir la superficie de ataque."))


def _audit_conexiones(conns, permiso):
    _sub("Conexiones establecidas")
    if not permiso:
        return _info("Sin permisos para listar conexiones.")

    est = [c for c in conns if c.status == psutil.CONN_ESTABLISHED and c.raddr]
    print(f"   Total establecidas : {len(est)}")

    externas = {}
    for c in est:
        try:
            if not ipaddress.ip_address(c.raddr.ip).is_global:
                continue
        except ValueError:
            continue
        name = _proc_info(c.pid)[0]
        externas[(name, c.raddr.ip, c.raddr.port)] = externas.get((name, c.raddr.ip, c.raddr.port), 0) + 1

    print(f"   Hacia Internet     : {len(externas)} destinos distintos\n")
    for (name, ip, port), n in sorted(externas.items())[:15]:
        print(f"   {CYAN}{name.ljust(22)}{RESET} → {ip}:{port}" + (f"  ×{n}" if n > 1 else ""))
    if len(externas) > 15:
        print(f"   {WHITE}... y {len(externas) - 15} más{RESET}")


def _audit_sesiones():
    _sub("Sesiones de usuario activas")
    try:
        users = psutil.users()
    except Exception:
        users = []
    if not users:
        return _info("Sin sesiones registradas (o sin permisos para verlas).")
    for u in users:
        desde = datetime.datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M")
        print(f"   {CYAN}{u.name.ljust(16)}{RESET} {(u.terminal or '-').ljust(10)} "
              f"{(u.host or 'local').ljust(18)} desde {desde}")


def _audit_procesos():
    _sub("Procesos con más uso de memoria (top 8)")
    procs = []
    for p in psutil.process_iter(["pid", "name", "memory_percent", "username"]):
        try:
            procs.append((p.info["memory_percent"] or 0.0, p.info["pid"],
                          p.info["name"] or "?", p.info["username"] or "-"))
        except Exception:
            continue
    for mem, pid, name, user in sorted(procs, reverse=True)[:8]:
        print(f"   {CYAN}{name[:24].ljust(24)}{RESET} pid {str(pid).ljust(7)} {mem:5.1f}% RAM   {user}")


def mod_localaudit():
    _section("Auditoría Local del Sistema")

    if psutil is None:
        print(f"{WHITE}Sistema{RESET}        : {platform.platform()}")
        print(f"{WHITE}Hostname{RESET}       : {socket.gethostname()}")
        return _need("psutil")

    findings = []
    t0 = time.time()
    _kv("Fecha / hora", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    secciones = [
        ("sistema", lambda: _audit_sistema(findings)),
        ("discos", lambda: _audit_discos(findings)),
        ("red", lambda: _audit_red(findings)),
        ("firewall", lambda: _audit_firewall(findings)),
    ]
    for nombre, fn in secciones:
        try:
            fn()
        except Exception as exc:
            _warn(f"No se pudo completar la sección '{nombre}': {exc}")

    conns, permiso = _get_connections()
    for nombre, fn in [
        ("puertos", lambda: _audit_puertos(conns, permiso, findings)),
        ("conexiones", lambda: _audit_conexiones(conns, permiso)),
        ("sesiones", _audit_sesiones),
        ("procesos", _audit_procesos),
    ]:
        try:
            fn()
        except Exception as exc:
            _warn(f"No se pudo completar la sección '{nombre}': {exc}")

    _print_findings(findings)
    print(f"\n{CYAN}[*]{RESET} Auditoría completada en {time.time() - t0:.1f}s")


# ---------------------------------------------------------------------------
# 4. Captura de salida para armar el REPORTE final
# ---------------------------------------------------------------------------
REPORT_LOG = []
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


class _Tee(io.TextIOBase):
    def __init__(self, *streams):
        self._streams = streams

    def write(self, s):
        for st in self._streams:
            st.write(s)
        return len(s)

    def flush(self):
        for st in self._streams:
            st.flush()


def _limpiar_salida(texto):
    """Saca códigos ANSI y deja solo el estado final de las líneas que se
    redibujan con \\r (barras de progreso), para que el reporte quede limpio."""
    texto = _ANSI_RE.sub("", texto)
    lineas = [l.split("\r")[-1] for l in texto.split("\n")]
    limpio = "\n".join(lineas)
    return re.sub(r"\n{3,}", "\n\n", limpio)


def run_and_log(label, func):
    """Ejecuta func() mostrando la salida normal en pantalla y, si hay un
    reporte abierto (ver REPORT_SESSION), la guarda también (sin códigos
    de color) para el generador de reportes. Si no hay ningún reporte
    abierto, la herramienta corre igual pero no se guarda nada: hay que
    abrir un reporte primero (tecla [C] en el menú principal). Si la
    herramienta falla o se interrumpe, lo que alcanzó a imprimir igual se
    guarda."""
    if not REPORT_SESSION["activo"]:
        func()
        return

    buf = io.StringIO()
    real_out = sys.__stdout__ or sys.stdout
    tee = _Tee(real_out, buf)
    old_stdout = sys.stdout
    sys.stdout = tee
    try:
        func()
    finally:
        sys.stdout = old_stdout
        plain = _limpiar_salida(buf.getvalue())
        if plain.strip():
            REPORT_LOG.append({
                "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
                "modulo": label,
                "salida": plain,
            })


def clear_report_log():
    REPORT_LOG.clear()


# ---------------------------------------------------------------------------
# 5. Sesión de reporte: Crear reporte / Cerrar reporte (menú principal)
# ---------------------------------------------------------------------------
# Mientras no haya un reporte abierto, lo que se corre en Diagnóstico y
# Geolocalización se ve en pantalla como siempre pero NO se guarda. Al
# abrir un reporte (nombre + fecha) empieza a quedar registrado todo lo
# que se ejecute, hasta que se cierra (pide fecha de cierre y en qué
# formato(s) exportarlo). Cerrar vacía REPORT_LOG para que un reporte
# nuevo no arrastre herramientas del anterior.
REPORT_SESSION = {
    "activo": False,
    "nombre": None,
    "fecha_inicio": None,
    "carpeta": None,
}

FORMATOS_DISPONIBLES = ("html", "txt", "json", "md")


def _sanear_nombre(nombre):
    """Deja un nombre de archivo seguro: letras/números/espacios -> '_',
    saca cualquier otro símbolo (de paso evita path traversal tipo '../')."""
    limpio = re.sub(r"[^A-Za-z0-9ÁÉÍÓÚÑáéíóúñ _-]", "", nombre).strip()
    limpio = re.sub(r"\s+", "_", limpio)
    return limpio or "sin_nombre"


def reporte_activo():
    return REPORT_SESSION["activo"]


def iniciar_reporte(nombre, fecha, out_dir="reportes"):
    _section("Crear Reporte")
    if REPORT_SESSION["activo"]:
        return _warn(f"Ya hay un reporte abierto: '{REPORT_SESSION['nombre']}'. "
                      f"Cerralo primero (opción [C] del menú principal) antes de abrir uno nuevo.")

    nombre_limpio = _sanear_nombre(nombre or "")
    fecha = (fecha or "").strip() or datetime.datetime.now().strftime("%Y-%m-%d")

    os.makedirs(out_dir, exist_ok=True)
    REPORT_LOG.clear()
    REPORT_SESSION.update({
        "activo": True,
        "nombre": nombre_limpio,
        "fecha_inicio": fecha,
        "carpeta": out_dir,
    })
    _ok(f"Reporte '{nombre_limpio}' abierto  ·  fecha : {fecha}")
    _info("A partir de ahora, todo lo que corras en Diagnóstico y Reporte / "
          "Geolocalización queda registrado acá.")
    _info("Cuando termines el relevamiento, volvé al menú principal y elegí "
          "[C] Cerrar reporte para exportarlo.")


def cerrar_reporte(fecha_cierre, formatos, out_dir=None):
    _section("Cerrar Reporte")
    if not REPORT_SESSION["activo"]:
        return _warn("No hay ningún reporte abierto. Primero abrilo con [C] Crear reporte.")

    if not REPORT_LOG:
        _warn("El reporte se cierra sin ningún módulo registrado (no se corrió nada mientras estuvo abierto).")

    formatos = [f for f in (formatos or []) if f in FORMATOS_DISPONIBLES] or ["html", "txt"]
    out_dir = out_dir or REPORT_SESSION["carpeta"] or "reportes"
    os.makedirs(out_dir, exist_ok=True)

    nombre = REPORT_SESSION["nombre"]
    fecha_inicio = REPORT_SESSION["fecha_inicio"]
    fecha_cierre = (fecha_cierre or "").strip() or datetime.datetime.now().strftime("%Y-%m-%d")
    # milisegundos incluidos: si se cierran dos reportes en el mismo segundo
    # (común al probar o en sesiones muy cortas), el nombre no debe colisionar.
    sello = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    basename = f"{nombre}_{sello}"

    meta = {
        "nombre": nombre,
        "fecha_inicio": fecha_inicio,
        "fecha_cierre": fecha_cierre,
        "generado": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cantidad_modulos": len(REPORT_LOG),
    }

    rutas = []
    if "html" in formatos:
        rutas.append(_escribir_reporte_html(out_dir, basename, meta))
    if "txt" in formatos:
        rutas.append(_escribir_reporte_txt(out_dir, basename, meta))
    if "json" in formatos:
        rutas.append(_escribir_reporte_json(out_dir, basename, meta))
    if "md" in formatos:
        rutas.append(_escribir_reporte_md(out_dir, basename, meta))

    _ok(f"Reporte '{nombre}'  ·  {fecha_inicio} → {fecha_cierre}")
    _ok(f"Módulos incluidos : {len(REPORT_LOG)}")
    for r in rutas:
        _ok(f"Generado : {r}")

    REPORT_LOG.clear()
    REPORT_SESSION.update({"activo": False, "nombre": None, "fecha_inicio": None, "carpeta": None})


# Se mantiene por compatibilidad (no se usa desde el menú, que ahora usa
# iniciar_reporte/cerrar_reporte): genera HTML+TXT de lo acumulado al toque,
# sin pasar por el ciclo de sesión.
def mod_report(out_dir="reportes", basename=None):
    _section("Generador de Reportes")
    if not REPORT_LOG:
        return _warn("Todavía no se registró ningún módulo para incluir en el reporte.")
    os.makedirs(out_dir, exist_ok=True)
    basename = basename or f"osighost_reporte_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    meta = {
        "nombre": basename,
        "fecha_inicio": "",
        "fecha_cierre": "",
        "generado": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cantidad_modulos": len(REPORT_LOG),
    }
    _ok(f"Reporte HTML : {_escribir_reporte_html(out_dir, basename, meta)}")
    _ok(f"Reporte TXT  : {_escribir_reporte_txt(out_dir, basename, meta)}")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Reporte OSIGhost{titulo_sufijo}</title>
<style>
  body {{ background:#0d0d0d; color:#eaeaea; font-family: Consolas, 'Courier New', monospace; margin:0; padding:2rem; }}
  h1 {{ color:#ff3b3b; border-bottom:1px solid #440000; padding-bottom:.5rem; }}
  .meta {{ color:#aaa; margin-bottom:2rem; }}
  .modulo {{ background:#161616; border-left:4px solid #ff3b3b; margin-bottom:1.5rem; padding:1rem 1.5rem; border-radius:4px; }}
  .modulo h2 {{ color:#ff6b6b; margin-top:0; font-size:1.1rem; }}
  .modulo .ts {{ color:#777; font-size:.85rem; margin-bottom:.8rem; }}
  pre {{ white-space:pre-wrap; word-break:break-word; font-size:.9rem; line-height:1.4; }}
</style>
</head>
<body>
<h1>Reporte de Seguridad &mdash; OSIGhost</h1>
<p class="meta">
  Nombre : {nombre}<br>
  Fecha inicio : {fecha_inicio} &nbsp;&middot;&nbsp; Fecha cierre : {fecha_cierre}<br>
  Generado : {generado}<br>
  Módulos ejecutados : {cantidad_modulos}
</p>
{bloques}
</body>
</html>
"""

BLOQUE_TEMPLATE = """<div class="modulo">
  <h2>{modulo}</h2>
  <div class="ts">{timestamp}</div>
  <pre>{salida}</pre>
</div>
"""


def _html_escape(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _escribir_reporte_html(out_dir, basename, meta):
    bloques = "".join(
        BLOQUE_TEMPLATE.format(
            modulo=_html_escape(e["modulo"]),
            timestamp=e["timestamp"],
            salida=_html_escape(e["salida"]),
        ) for e in REPORT_LOG
    )
    titulo_sufijo = f" — {meta['nombre']}" if meta.get("nombre") else ""
    html = HTML_TEMPLATE.format(titulo_sufijo=titulo_sufijo, bloques=bloques, **meta)
    path = os.path.join(out_dir, basename + ".html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def _escribir_reporte_txt(out_dir, basename, meta):
    path = os.path.join(out_dir, basename + ".txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"REPORTE OSIGHOST - {meta['nombre']}\n")
        f.write(f"Fecha inicio : {meta['fecha_inicio']}    Fecha cierre : {meta['fecha_cierre']}\n")
        f.write(f"Generado     : {meta['generado']}\n")
        f.write("=" * 60 + "\n\n")
        for e in REPORT_LOG:
            f.write(f"[{e['timestamp']}] {e['modulo']}\n")
            f.write("-" * 60 + "\n")
            f.write(e["salida"] + "\n\n")
    return path


def _escribir_reporte_json(out_dir, basename, meta):
    path = os.path.join(out_dir, basename + ".json")
    data = {**meta, "modulos": REPORT_LOG}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def _escribir_reporte_md(out_dir, basename, meta):
    path = os.path.join(out_dir, basename + ".md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Reporte OSIGhost — {meta['nombre']}\n\n")
        f.write(f"- **Fecha inicio:** {meta['fecha_inicio']}\n")
        f.write(f"- **Fecha cierre:** {meta['fecha_cierre']}\n")
        f.write(f"- **Generado:** {meta['generado']}\n")
        f.write(f"- **Módulos ejecutados:** {meta['cantidad_modulos']}\n\n")
        for e in REPORT_LOG:
            f.write(f"## {e['modulo']}\n")
            f.write(f"*{e['timestamp']}*\n\n")
            f.write("```\n" + e["salida"].rstrip() + "\n```\n\n")
    return path


# ---------------------------------------------------------------------------
# 6. Escaneo avanzado vía nmap (SYN scan, UDP, fingerprint de SO, NSE)
# ---------------------------------------------------------------------------
# Estas técnicas necesitan sockets crudos (privilegios root/admin) y el
# motor de huellas/scripts de nmap -- no tiene sentido reimplementarlas en
# Python puro, así que se delega al binario real de nmap si está instalado.
# Igual que el resto de OSIGhost: nada de --script con categorías de
# explotación/ataque, solo detección (vuln = *detecta* CVEs conocidos por
# firma/versión, no los explota; default/discovery = enumeración de solo
# lectura).
def _nmap_disponible():
    return shutil.which("nmap") is not None


def _ejecutar_nmap(args, descripcion, requiere_root=False, timeout=None):
    if not _nmap_disponible():
        _err("nmap no está instalado en este sistema.")
        _info("Instalalo con: sudo apt install nmap   (Termux: pkg install nmap  ·  Windows: nmap.org)")
        return
    if requiere_root and not _is_admin():
        _warn(f"{descripcion} necesita privilegios de administrador/root para armar paquetes crudos.")
        _info("Volvé a correr OSIGhost con 'sudo' (Linux/Termux) o como Administrador (Windows).")
        return

    cmd = ["nmap"] + args
    _info("Comando : " + " ".join(cmd))
    _info("Ctrl+C corta el escaneo y deja lo que nmap alcanzó a imprimir.")
    print()

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, errors="replace", bufsize=1)
        for line in proc.stdout:
            print(line.rstrip())
        proc.wait(timeout=timeout)
    except KeyboardInterrupt:
        if proc:
            proc.terminate()
        _warn("Escaneo interrumpido por el usuario.")
    except FileNotFoundError:
        _err("No se encontró el binario de nmap.")
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
        _warn("Escaneo cortado por timeout.")


def mod_nmap_scan(host, modo):
    _section(f"Escaneo Avanzado (nmap) ─ {host}")

    if modo == "syn":
        _ejecutar_nmap(["-sS", "-Pn", "--top-ports", "1000", "-T4", host],
                        "El SYN scan (-sS)", requiere_root=True)
    elif modo == "udp":
        _ejecutar_nmap(["-sU", "--top-ports", "100", "-T4", host],
                        "El escaneo UDP (-sU)", requiere_root=True)
    elif modo == "os":
        _ejecutar_nmap(["-O", "-Pn", host],
                        "El fingerprint de SO (-O)", requiere_root=True)
    elif modo == "vuln":
        _ejecutar_nmap(["-sV", "-Pn", "--script=vuln", "-T4", host],
                        "Los scripts NSE de vulnerabilidades", requiere_root=False)
    elif modo == "discovery":
        _ejecutar_nmap(["-sV", "-sC", "-Pn", "-T4", host],
                        "Los scripts NSE de descubrimiento", requiere_root=False)
    elif modo == "full":
        _info("Escaneo completo: todos los puertos + versión + SO + scripts. Puede tardar varios minutos.")
        _ejecutar_nmap(["-sS", "-sV", "-O", "-p-", "--min-rate=1000", "-T4",
                         "--script=default,vuln", host],
                        "El escaneo completo profesional", requiere_root=True, timeout=1800)
    else:
        _err(f"Modo de escaneo desconocido: '{modo}'")


# ---------------------------------------------------------------------------
# 7. Contenedores / Docker expuesto
# ---------------------------------------------------------------------------
# Solo lectura: consulta endpoints de la propia API de Docker que, si el
# motor está mal configurado, responden SIN autenticación (/version,
# /containers/json, y el catálogo de un Registry v2). No se crea, ejecuta
# ni modifica ningún contenedor -- es detección de la misma exposición que
# ya explotan botnets automatizadas que escanean 2375/5000 todo el tiempo.
def mod_docker_check(host):
    _section(f"Contenedores / Docker Expuesto ─ {host}")

    _sub("Puertos del Engine API")
    _, abierto_2375, _ = _scan_one(host, 2375, 1.5)
    _, abierto_2376, _ = _scan_one(host, 2376, 1.5)
    print(f"   {GREEN if abierto_2375 else WHITE}2375/tcp{RESET} (API sin TLS)  "
          f"{'ABIERTO' if abierto_2375 else 'cerrado'}")
    print(f"   {GREEN if abierto_2376 else WHITE}2376/tcp{RESET} (API con TLS)  "
          f"{'ABIERTO' if abierto_2376 else 'cerrado'}")

    if abierto_2375 and requests is None:
        _warn("2375 está abierto pero falta 'requests' para confirmar si es la API sin autenticar.")
    elif abierto_2375:
        _sub("Docker API sin TLS — probando acceso sin autenticación")
        try:
            r = requests.get(f"http://{host}:2375/version", timeout=6)
        except Exception as exc:
            r = None
            _info(f"El puerto está abierto pero no se pudo leer /version : {exc}")
        if r is not None and r.status_code == 200 and "ApiVersion" in r.text:
            try:
                data = r.json()
            except Exception:
                data = {}
            _err(f"CRÍTICO: API Docker expuesta SIN autenticación. "
                 f"Versión del motor : {data.get('Version', '?')}  ·  API : {data.get('ApiVersion', '?')}")
            try:
                rc = requests.get(f"http://{host}:2375/containers/json?all=1", timeout=6)
                if rc.status_code == 200:
                    conts = rc.json()
                    _err(f"CRÍTICO: se pueden listar los contenedores sin credenciales ({len(conts)} encontrados).")
                    for c in conts[:10]:
                        nombre = (c.get("Names") or ["?"])[0]
                        print(f"   {RED}{nombre}{RESET}  {c.get('Image', '?')}  ({c.get('State', '?')})")
                    if len(conts) > 10:
                        _info(f"... y {len(conts) - 10} más (truncado en pantalla).")
            except Exception:
                pass
        elif r is not None:
            _ok("El puerto 2375 responde pero no parece ser la API de Docker sin autenticar.")

    if abierto_2376:
        _info("2376 (TLS) abierto: por diseño pide certificado de cliente, no se puede confirmar "
              "exposición sin credenciales desde acá.")

    if not abierto_2375 and not abierto_2376:
        _ok("Ningún puerto del Engine API (2375/2376) está abierto.")

    if requests is not None:
        _sub("Registro de imágenes (Docker Registry v2) en :5000")
        try:
            r = requests.get(f"http://{host}:5000/v2/_catalog", timeout=6)
        except Exception:
            r = None
        if r is not None and r.status_code == 200 and "repositories" in r.text:
            try:
                data = r.json()
            except Exception:
                data = {}
            repos = data.get("repositories", [])
            _err(f"CRÍTICO: registry expuesto sin autenticación ({len(repos)} imágenes listadas).")
            for repo in repos[:10]:
                print(f"   {RED}{repo}{RESET}")
        else:
            _ok("El puerto 5000 no expone un catálogo de registry sin autenticar.")

    _info("Nota: 'docker-compose.yml' expuesto por HTTP ya lo cubre la herramienta 'Fuerza de Directorios'.")


# ---------------------------------------------------------------------------
# 8. Búsqueda de CVEs (NVD) — cruza producto/versión con vulnerabilidades
#    conocidas y les trae el score CVSS.
# ---------------------------------------------------------------------------
def mod_cve_lookup(keyword, max_resultados=10):
    _section(f"Búsqueda de CVEs (NVD) ─ {keyword}")
    if requests is None:
        return _need("requests", "requests")

    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_resultados},
            headers=USER_AGENT, timeout=15,
        )
    except Exception as exc:
        return _err(f"No se pudo consultar la NVD : {exc}")

    if r.status_code == 404:
        return _warn("Sin resultados para esa búsqueda.")
    if r.status_code == 429:
        return _warn("La NVD limitó la consulta (rate limit público, sin API key). Esperá un minuto y reintentá.")
    if r.status_code != 200:
        return _err(f"La NVD respondió {r.status_code}.")

    try:
        data = r.json()
    except Exception:
        return _err("Respuesta inesperada de la NVD (no es JSON válido).")

    total = data.get("totalResults", 0)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return _ok(f"Sin CVEs encontrados para '{keyword}'.")

    _info(f"{total} resultado(s) totales en la NVD  ·  mostrando {len(vulns)}")
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "?")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

        score, severidad = None, None
        for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrica = cve.get("metrics", {}).get(clave)
            if metrica:
                cvss = metrica[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severidad = metrica[0].get("baseSeverity") or cvss.get("baseSeverity")
                break

        color = RED if (score or 0) >= 7 else (YELLOW if (score or 0) >= 4 else CYAN)
        print(f"\n   {color}{cve_id}{RESET}  CVSS: {score if score is not None else '?'} ({severidad or '?'})")
        if desc:
            texto = desc if len(desc) <= 220 else desc[:220] + "…"
            print(f"   {WHITE}{texto}{RESET}")

    _info("Fuente: NVD (services.nvd.nist.gov) — consulta pública de solo lectura, sin API key.")


# ---------------------------------------------------------------------------
# 9. Gestión de Reportes: comparar dos reportes y exportar hallazgos a
#    formato de ticket (CSV / CSV para importar en Jira).
# ---------------------------------------------------------------------------
def _cargar_reporte_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def comparar_reportes(path_a, path_b):
    _section("Comparar Reportes")
    try:
        a = _cargar_reporte_json(path_a)
        b = _cargar_reporte_json(path_b)
    except FileNotFoundError as exc:
        return _err(f"No se encontró el archivo : {exc.filename}")
    except json.JSONDecodeError:
        return _err("Alguno de los dos archivos no es un reporte JSON válido "
                     "(hay que haberlo cerrado eligiendo el formato JSON).")

    _info(f"Reporte A : {a.get('nombre', '?')}  ({a.get('fecha_inicio', '?')} → {a.get('fecha_cierre', '?')})")
    _info(f"Reporte B : {b.get('nombre', '?')}  ({b.get('fecha_inicio', '?')} → {b.get('fecha_cierre', '?')})")

    mods_a = {m["modulo"]: m["salida"] for m in a.get("modulos", [])}
    mods_b = {m["modulo"]: m["salida"] for m in b.get("modulos", [])}
    solo_a = sorted(set(mods_a) - set(mods_b))
    solo_b = sorted(set(mods_b) - set(mods_a))
    comunes = sorted(set(mods_a) & set(mods_b))

    if solo_a:
        _sub(f"Módulos que estaban en A y no se corrieron en B ({len(solo_a)})")
        for m in solo_a:
            print(f"   {YELLOW}{m}{RESET}")
    if solo_b:
        _sub(f"Módulos nuevos en B, no estaban en A ({len(solo_b)})")
        for m in solo_b:
            print(f"   {GREEN}{m}{RESET}")

    _sub(f"Diferencias en módulos presentes en ambos reportes ({len(comunes)})")
    sin_cambios = 0
    for m in comunes:
        diff = list(difflib.unified_diff(
            mods_a[m].splitlines(), mods_b[m].splitlines(),
            fromfile="A", tofile="B", lineterm="", n=0,
        ))
        if not diff:
            sin_cambios += 1
            continue
        print(f"\n   {WHITE}❯ {m}{RESET}")
        for linea in diff[2:32]:
            if linea.startswith("+"):
                print(f"     {GREEN}{linea}{RESET}")
            elif linea.startswith("-"):
                print(f"     {RED}{linea}{RESET}")
            else:
                print(f"     {linea}")
        if len(diff) > 32:
            print(f"     {CYAN}... diff truncado en pantalla ({len(diff) - 32} líneas más){RESET}")

    _ok(f"Módulos sin cambios : {sin_cambios}/{len(comunes)}")


# Líneas con severidad ya marcada por las propias herramientas de OSIGhost
# (formato "[CRÍTICO]/[ALTO]/[MEDIO]/[BAJO]" de _print_findings, o la marca
# puntual "⚠ CRÍTICO" que usa Fuerza de Directorios para archivos sensibles).
_SEV_LINE_RE = re.compile(r"\[(CRÍTICO|ALTO|MEDIO|BAJO)\]")
_SEV_TAG_RE = re.compile(r"⚠\s*CRÍTICO")
JIRA_PRIORIDAD = {"CRÍTICO": "Highest", "ALTO": "High", "MEDIO": "Medium", "BAJO": "Low"}


def _extraer_hallazgos(modulos):
    hallazgos = []
    for mod in modulos:
        nombre = mod.get("modulo", "?")
        for linea in mod.get("salida", "").splitlines():
            texto = linea.strip()
            if not texto:
                continue
            m = _SEV_LINE_RE.search(texto)
            sev = m.group(1) if m else ("CRÍTICO" if _SEV_TAG_RE.search(texto) else None)
            if sev:
                hallazgos.append({"severidad": sev, "modulo": nombre, "descripcion": texto})
    return hallazgos


def exportar_hallazgos(path_reporte, formato="csv", out_dir="reportes"):
    _section("Exportar Hallazgos a Ticket")
    try:
        data = _cargar_reporte_json(path_reporte)
    except FileNotFoundError:
        return _err(f"No se encontró el archivo : {path_reporte}")
    except json.JSONDecodeError:
        return _err("El archivo no es un reporte JSON válido.")

    hallazgos = _extraer_hallazgos(data.get("modulos", []))
    if not hallazgos:
        return _warn("No se encontraron líneas con severidad marcada "
                      "([CRÍTICO]/[ALTO]/[MEDIO]/[BAJO]) en ese reporte.")

    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(path_reporte))[0]

    if formato == "jira":
        path = os.path.join(out_dir, base + "_jira.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Summary", "Issue Type", "Priority", "Description", "Labels"])
            for h in hallazgos:
                w.writerow([h["descripcion"][:120], "Bug", JIRA_PRIORIDAD.get(h["severidad"], "Medium"),
                            h["descripcion"], f"osighost,{h['modulo'].replace(' ', '_')}"])
    else:
        path = os.path.join(out_dir, base + "_hallazgos.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Severidad", "Módulo", "Descripción"])
            for h in hallazgos:
                w.writerow([h["severidad"], h["modulo"], h["descripcion"]])

    counts = {}
    for h in hallazgos:
        counts[h["severidad"]] = counts.get(h["severidad"], 0) + 1
    resumen = "  ".join(f"{SEV_COLOR.get(s, WHITE)}{s}: {c}{RESET}" for s, c in counts.items())
    _ok(f"Hallazgos exportados : {len(hallazgos)}   ({resumen})")
    _ok(f"Archivo : {path}")
