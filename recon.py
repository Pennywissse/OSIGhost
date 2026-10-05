#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSIGhost - Módulo RECON WEB (Opción 1)
Reconocimiento pasivo/activo sobre un dominio o IP objetivo: headers,
SSL, WHOIS, DNS, subdominios, crawler, fuerza de directorios y Wayback
Machine. Reescrito con la sintaxis y colores propios de OSIGhost a partir
de técnicas estándar de reconocimiento web (headers HTTP, WHOIS, DNS,
Certificate Transparency, CDX de archive.org).

Sin asyncio/aiohttp a propósito: todo corre sobre requests + hilos
(ThreadPoolExecutor), que es más liviano y portable en Termux.
"""

import ipaddress
import os
import random
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from json import loads
from urllib.parse import urlparse, parse_qs

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

try:
    import tldextract
    # Sin esto, tldextract intenta bajar la lista de sufijos públicos de
    # internet la primera vez que corre. Con suffix_list_urls=() usa el
    # snapshot que ya viene empaquetado con la librería (offline y rápido).
    _tld = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    tldextract = None
    _tld = None

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    x509 = None

try:
    import dns.resolver
except ImportError:
    dns = None

from osighost import RED, WHITE, RESET, GREEN, YELLOW, CYAN
import netsec

HERE = os.path.dirname(os.path.realpath(__file__))
WORDLIST_PATH = os.path.join(HERE, "wordlists", "common.txt")

USER_AGENT = {"User-Agent": "OSIGhost/1.0"}
TIMEOUT = 10


# ---------------------------------------------------------------------------
# Helpers de impresión (sintaxis OSIGhost)
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


def _sub(title):
    print(f"\n{WHITE}❯ {title}{RESET}\n")


def _need(mod_name, pip_name):
    _err(f"Falta el módulo '{pip_name}'. Instalá dependencias: pip install -r requirements.txt")


# ---------------------------------------------------------------------------
# Normalización del objetivo
# ---------------------------------------------------------------------------
class Target:
    def __init__(self, raw):
        raw = raw.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "http://" + raw
        if raw.endswith("/"):
            raw = raw[:-1]

        split = urlparse(raw)
        self.url = raw
        self.protocol = split.scheme
        self.hostname = split.hostname
        self.port = split.port
        self.is_ip = False
        self.domain = ""
        self.suffix = ""
        self.apex = ""

        try:
            ipaddress.ip_address(self.hostname)
            self.is_ip = True
            self.ip = self.hostname
        except ValueError:
            self.ip = socket.gethostbyname(self.hostname)

        if not self.is_ip and _tld is not None:
            ext = _tld(self.hostname)
            self.domain = ext.domain
            self.suffix = ext.suffix
            self.apex = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        elif not self.is_ip:
            parts = self.hostname.split(".")
            self.apex = ".".join(parts[-2:]) if len(parts) >= 2 else self.hostname
            self.domain, _, self.suffix = self.apex.partition(".")


def build_target(raw):
    try:
        return Target(raw), None
    except socket.gaierror as exc:
        return None, f"No se pudo resolver el host : {exc}"
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# 1. Headers HTTP
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy",
    "Content-Security-Policy-Report-Only", "Strict-Transport-Security",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
}
REQUIRED_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Content-Security-Policy": "CSP",
    "Referrer-Policy": "Referrer-Policy",
}


def mod_headers(tgt):
    _section("Headers HTTP")
    if requests is None:
        return _need("requests", "requests")
    try:
        resp = requests.get(tgt.url, headers=USER_AGENT, verify=False, timeout=TIMEOUT)
    except Exception as exc:
        return _err(f"Excepción : {exc}")

    hdrs = resp.headers
    general = {k: v for k, v in hdrs.items() if k not in SECURITY_HEADERS and k != "Set-Cookie"}
    print(f"{WHITE}❯ General{RESET}\n")
    for k, v in general.items():
        print(f"   {CYAN}{k.ljust(28)}{RESET} : {v}")

    sec = {k: v for k, v in hdrs.items() if k in SECURITY_HEADERS}
    if sec:
        print(f"\n{WHITE}❯ Seguridad{RESET}\n")
        for k, v in sec.items():
            print(f"   {YELLOW}{k.ljust(28)}{RESET} : {v}")

    missing = [label for h, label in REQUIRED_HEADERS.items() if h not in hdrs]
    if missing:
        print(f"\n{WHITE}❯ Faltantes{RESET}\n")
        for label in missing:
            print(f"   {RED}{label}{RESET}")

    cookies = resp.raw.headers.getlist("Set-Cookie") if resp.raw else []
    if cookies:
        print(f"\n{WHITE}❯ Cookies{RESET}\n")
        for cookie in cookies:
            parts = [p.strip() for p in cookie.split(";")]
            name = parts[0].split("=")[0]
            attrs = {p.split("=")[0].strip(): True for p in parts[1:]}
            secure = f"{GREEN}✓{RESET}" if "Secure" in attrs else f"{RED}✗{RESET}"
            httponly = f"{GREEN}✓{RESET}" if "HttpOnly" in attrs else f"{RED}✗{RESET}"
            print(f"   {CYAN}{name.ljust(20)}{RESET} Secure={secure} HttpOnly={httponly}")


# ---------------------------------------------------------------------------
# 2. SSL / TLS
# ---------------------------------------------------------------------------
def _match_hostname(hostname, names):
    """Chequeo manual (sin librerías) de hostname contra CN/SAN, con
    soporte de wildcard tipo '*.ejemplo.com'."""
    hostname = hostname.lower()
    for name in names:
        name = name.lower()
        if name == hostname:
            return True
        if name.startswith("*."):
            resto = name[2:]
            if hostname.count(".") == resto.count(".") + 1 and hostname.endswith("." + resto):
                return True
    return False


def _cert_trust_check(hostname, port):
    """Intenta una conexión TLS con verificación REAL (cadena de
    confianza del sistema + hostname), separado de la conexión principal
    que va sin verificar para poder leer el certificado aunque no sea
    confiable. Devuelve (confiable, detalle_del_error_o_None)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                pass
        return True, None
    except Exception as exc:
        return False, str(exc)


def mod_sslinfo(tgt, port=443):
    _section("TLS / SSL")
    if x509 is None:
        return _need("cryptography", "cryptography")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((tgt.hostname, port))
        sock.close()
    except Exception:
        return _warn("El objetivo no tiene SSL en ese puerto, se omite.")

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.socket()
        raw.settimeout(5)
        conn = ctx.wrap_socket(raw, server_hostname=tgt.hostname)
        conn.connect((tgt.hostname, port))
        der = conn.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der, default_backend())

        subject = {a.oid._name: a.value for a in cert.subject}
        issuer = {a.oid._name: a.value for a in cert.issuer}

        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        print(f"{WHITE}Sujeto{RESET}")
        for k, v in subject.items():
            print(f"   └╴{k} : {v}")
        print(f"\n{WHITE}Emisor{RESET}")
        for k, v in issuer.items():
            print(f"   └╴{k} : {v}")

        self_signed = subject == issuer
        if self_signed:
            print(f"\n{RED}[!] Certificado AUTOFIRMADO{RESET} (sujeto == emisor)")

        color = RED if days_left < 15 else YELLOW if days_left < 30 else GREEN
        print(f"\n{WHITE}Protocolo{RESET}       : {conn.version()}")
        print(f"{WHITE}Cifrado (sesión){RESET} : {conn.cipher()[0] if conn.cipher() else 'n/d'}")
        print(f"{WHITE}Válido desde{RESET}     : {not_before.strftime('%Y-%m-%d')}")
        print(f"{WHITE}Válido hasta{RESET}     : {color}{not_after.strftime('%Y-%m-%d')} ({days_left} días){RESET}")

        # Algoritmo y tamaño de la clave pública + algoritmo de firma: un
        # RSA < 2048 bits o firma con hash débil (MD5/SHA1) es un hallazgo.
        try:
            pub = cert.public_key()
            if hasattr(pub, "key_size"):
                tipo = type(pub).__name__.replace("PublicKey", "").replace("_", "")
                size = pub.key_size
                weak = tipo.upper().startswith("RSA") and size < 2048
                col = RED if weak else WHITE
                print(f"{WHITE}Clave pública{RESET}    : {col}{tipo} {size} bits{RESET}" +
                      (f"  {RED}(débil, se recomienda ≥2048){RESET}" if weak else ""))
        except Exception:
            pass

        sig_alg = getattr(cert.signature_hash_algorithm, "name", "") if cert.signature_hash_algorithm else ""
        if sig_alg:
            weak_sig = sig_alg.lower() in ("md5", "sha1")
            col = RED if weak_sig else WHITE
            print(f"{WHITE}Firma{RESET}            : {col}{sig_alg}{RESET}" +
                  (f"  {RED}(hash débil/roto){RESET}" if weak_sig else ""))

        sans = []
        for ext in cert.extensions:
            if ext.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                sans = [n.value for n in ext.value if isinstance(n, x509.DNSName)]
                print(f"\n{WHITE}Nombres alternativos (SAN){RESET}")
                for n in sans:
                    print(f"   └╴{n}")

        cn = subject.get("commonName", "")
        nombres_cert = sans or ([cn] if cn else [])
        coincide = _match_hostname(tgt.hostname, nombres_cert) if nombres_cert else False
        print(f"\n{WHITE}Coincide con {tgt.hostname}{RESET} : " +
              (f"{GREEN}sí{RESET}" if coincide else f"{RED}NO (posible mismatch de hostname){RESET}"))
    except Exception as exc:
        _err(f"Excepción : {exc}")

    # Cadena de confianza REAL (certificado del sistema, no el que acabamos
    # de leer sin verificar): dice si un navegador confiaría en este cert.
    confiable, detalle = _cert_trust_check(tgt.hostname, port)
    if confiable:
        _ok("Cadena de confianza: válida (confiable con los certificados raíz del sistema)")
    else:
        _err(f"Cadena de confianza: NO válida ─ {detalle}")

    # Además del certificado: qué versiones de TLS/SSL y qué cifrados
    # débiles acepta el servidor (hardening, no solo info del cert).
    try:
        netsec.audit_tls_protocols_and_ciphers(tgt.hostname, port)
    except Exception as exc:
        _warn(f"No se pudo completar la auditoría de protocolos/cifrados : {exc}")


# ---------------------------------------------------------------------------
# 3. WHOIS (genérico vía bootstrap de IANA, sin JSON gigante)
# ---------------------------------------------------------------------------
def _raw_whois(server, query, port=43):
    with socket.create_connection((server, port), timeout=8) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="replace")


# ---------------------------------------------------------------------------
# 3a. RDAP (HTTPS, puerto 443) — reemplazo moderno y estandarizado de WHOIS.
#     Se intenta primero porque el WHOIS clásico usa el puerto 43, que
#     muchas redes corporativas/móviles/VPN bloquean (causa más común de
#     que "no funcione"). RDAP viaja por HTTPS como cualquier otra web.
# ---------------------------------------------------------------------------
def _rdap_lookup(domain):
    if requests is None:
        return None
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=USER_AGENT, timeout=10)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def _rdap_vcard_field(vcard_array, key="fn"):
    try:
        for entry in vcard_array[1]:
            if entry[0] == key:
                return entry[3]
    except Exception:
        pass
    return None


def _print_rdap(data):
    _kv2("Dominio", data.get("ldhName", "-"))

    status = data.get("status") or []
    if status:
        _kv2("Estado", ", ".join(status))

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if e.get("eventAction")}
    labels = [
        ("registration", "Creación"),
        ("last changed", "Última modificación"),
        ("expiration", "Expiración"),
        ("transfer", "Última transferencia"),
    ]
    now = datetime.now(timezone.utc)
    for action, label in labels:
        val = events.get(action)
        if not val:
            continue
        color, suffix = WHITE, ""
        if action == "expiration":
            try:
                exp = datetime.fromisoformat(val.replace("Z", "+00:00"))
                days = (exp - now).days
                color = RED if days < 30 else YELLOW if days < 90 else GREEN
                suffix = f" ({days} días)"
            except Exception:
                pass
        _kv2(label, f"{val}{suffix}", color)

    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            registrar = _rdap_vcard_field(ent.get("vcardArray", [None, []]))
            if not registrar:
                for pid in ent.get("publicIds", []):
                    if pid.get("type") == "IANA Registrar ID":
                        registrar = f"IANA ID {pid.get('identifier')}"
            break
    if registrar:
        _kv2("Registrador", registrar)

    ns = sorted(n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName"))
    if ns:
        _kv2("Servidores DNS", ", ".join(ns))

    secure = data.get("secureDNS") or {}
    if "delegationSigned" in secure:
        signed = secure["delegationSigned"]
        _kv2("DNSSEC", "firmado" if signed else "NO firmado", GREEN if signed else YELLOW)


def _kv2(label, value, color=WHITE):
    print(f"{CYAN}{label.ljust(24)}{RESET} : {color}{value}{RESET}")


# ---------------------------------------------------------------------------
# 3b. WHOIS clásico (puerto 43) — fallback si RDAP no responde. Sigue hasta
#     dos saltos de referencia (IANA → registro → registrador, cuando el
#     registro es "thin" y delega el detalle al registrador) y reconoce
#     muchas variantes de nombres de campo, no solo el formato de Verisign.
# ---------------------------------------------------------------------------
WHOIS_KEY_ALIASES = {
    "domain name": "Dominio",
    "registrar": "Registrador",
    "sponsoring registrar": "Registrador",
    "registrar url": "URL del registrador",
    "creation date": "Creación", "created": "Creación", "created on": "Creación",
    "registered on": "Creación", "registration date": "Creación",
    "updated date": "Última modificación", "last modified": "Última modificación",
    "changed": "Última modificación", "last updated": "Última modificación",
    "registry expiry date": "Expiración",
    "registrar registration expiration date": "Expiración",
    "expiry date": "Expiración", "expiration date": "Expiración",
    "expire date": "Expiración", "paid-till": "Expiración",
    "domain status": "Estado", "status": "Estado",
    "name server": "Servidor DNS", "nserver": "Servidor DNS",
    "dnssec": "DNSSEC",
}
_REFER_RE = re.compile(r"^(?:refer|whois):\s*(\S+)", re.I | re.M)
_REGISTRAR_WHOIS_RE = re.compile(r"^Registrar WHOIS Server:\s*(\S+)", re.I | re.M)


def _classic_whois_raw(domain, suffix):
    """Devuelve lista de (servidor, texto_crudo) con 1 o 2 saltos, o
    (None, mensaje_de_error)."""
    try:
        bootstrap = _raw_whois("whois.iana.org", suffix)
    except Exception as exc:
        return None, f"No se pudo contactar whois.iana.org : {exc}"

    m = _REFER_RE.search(bootstrap)
    if not m:
        return None, "IANA no tiene un servidor WHOIS delegado para este TLD."
    refer = m.group(1)

    try:
        raw = _raw_whois(refer, domain)
    except Exception as exc:
        return None, f"No se pudo contactar {refer} (puerto 43 ¿bloqueado por tu red?) : {exc}"

    textos = [(refer, raw)]
    m2 = _REGISTRAR_WHOIS_RE.search(raw)
    if m2 and m2.group(1).lower() != refer.lower():
        try:
            raw2 = _raw_whois(m2.group(1), domain)
            textos.append((m2.group(1), raw2))
        except Exception:
            pass  # el segundo salto es un plus; si falla nos quedamos con el primero
    return textos, None


def _classic_whois(domain, suffix):
    textos, error = _classic_whois_raw(domain, suffix)
    if error:
        return _err(error)

    vistos = set()
    campos = []
    crudo_fallback = None
    for servidor, raw in textos:
        if not raw.strip() or "no match for" in raw.lower() or "not found" in raw.lower():
            continue
        if crudo_fallback is None:
            crudo_fallback = raw
        for line in raw.splitlines():
            line = line.strip()
            if ":" not in line or line.startswith("%") or line.startswith("#"):
                continue
            key, _, val = line.partition(":")
            key, val = key.strip().lower(), val.strip()
            label = WHOIS_KEY_ALIASES.get(key)
            if not label or not val:
                continue
            if (label, val) in vistos:
                continue
            vistos.add((label, val))
            campos.append((label, val))

    if not campos:
        if crudo_fallback:
            _warn("No se reconocieron campos con nombres estándar. Respuesta cruda del servidor:")
            print()
            for line in [l for l in crudo_fallback.splitlines() if l.strip()][:20]:
                print(f"   {WHITE}{line.strip()}{RESET}")
        else:
            _warn("Dominio sin registro público o sin datos para mostrar.")
        return

    for label, val in campos:
        color, suffix_txt = WHITE, ""
        if label == "Expiración":
            try:
                expiry = datetime.fromisoformat(val.replace("Z", "+00:00"))
                days = (expiry - datetime.now(timezone.utc)).days
                color = RED if days < 30 else YELLOW if days < 90 else GREEN
                suffix_txt = f" ({days} días)"
            except Exception:
                pass
        elif label == "DNSSEC" and val.lower() in ("unsigned", "no"):
            color = YELLOW
        print(f"{CYAN}{label.ljust(24)}{RESET} : {color}{val}{suffix_txt}{RESET}")


def mod_whois(tgt):
    _section("WHOIS")
    if tgt.is_ip:
        return _warn("WHOIS de IP no soportado en este módulo, usá RDAP manualmente.")

    domain = tgt.apex or tgt.hostname

    data = _rdap_lookup(domain)
    if data:
        _ok("Datos obtenidos vía RDAP (HTTPS) — más completo y confiable que el WHOIS clásico")
        print()
        _print_rdap(data)
        return

    _warn("RDAP no respondió para este dominio. Probando WHOIS clásico (puerto 43)...")
    print()
    try:
        _classic_whois(domain, tgt.suffix)
    except Exception as exc:
        _err(f"Excepción : {exc}")


# ---------------------------------------------------------------------------
# 4. DNS
# ---------------------------------------------------------------------------
DNS_RECORDS = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail",
                   "smtp", "dkim", "s1", "s2", "mandrill", "mailgun"]


def _txt_values(resolver, name):
    try:
        answer = resolver.resolve(name, "TXT")
        return [b"".join(r.strings).decode(errors="replace") if hasattr(r, "strings")
                else r.to_text().strip('"') for r in answer]
    except Exception:
        return []


def _check_zone_transfer(domain, ns_hosts, findings):
    """Intenta AXFR (transferencia de zona) contra cada NS. Es una técnica
    de reconocimiento estándar y de solo lectura: si un servidor mal
    configurado la permite, es un hallazgo CRÍTICO (expone TODA la zona:
    subdominios internos, hosts que no deberían ser públicos, etc.)."""
    import dns.zone
    import dns.query

    _sub("Transferencia de zona (AXFR)")
    algun_exito = False
    for ns in ns_hosts:
        ns_clean = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain, timeout=6, lifetime=8))
            nombres = list(z.nodes.keys())
            algun_exito = True
            print(f"   {RED}{ns_clean.ljust(28)}{RESET} AXFR PERMITIDA ─ {len(nombres)} registros expuestos")
            findings_msg = f"El servidor {ns_clean} permite transferencia de zona AXFR sin restricción"
            findings.append(("CRÍTICO", "DNS", findings_msg))
        except Exception:
            print(f"   {GREEN}{ns_clean.ljust(28)}{RESET} rechazada (correcto)")
    if not algun_exito:
        _ok("Ningún servidor NS permite AXFR sin autenticar (correcto).")


def mod_dns(tgt):
    _section("Enumeración DNS")
    if dns is None:
        return _need("dnspython", "dnspython")

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    domain = tgt.apex or tgt.hostname
    findings = []

    _sub("Registros estándar")
    any_record = False
    ns_hosts, resolved_ips = [], []
    for rtype in DNS_RECORDS:
        try:
            answer = resolver.resolve(domain, rtype)
            for rec in answer:
                any_record = True
                print(f"{GREEN}{rtype.ljust(8)}{RESET} : {rec.to_text()}")
                if rtype == "NS":
                    ns_hosts.append(rec.to_text())
                elif rtype in ("A", "AAAA"):
                    resolved_ips.append(rec.to_text())
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return _err("El dominio no existe (NXDOMAIN).")
        except Exception as exc:
            _warn(f"{rtype} : {exc}")
    if not any_record:
        _warn("Sin registros DNS resueltos para los tipos estándar.")

    # --- DNS inverso de las IPs resueltas -----------------------------------
    if resolved_ips:
        _sub("DNS inverso (PTR) de las IPs resueltas")
        for ip in resolved_ips:
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                print(f"   {CYAN}{ip.ljust(18)}{RESET} → {ptr}")
            except Exception:
                print(f"   {CYAN}{ip.ljust(18)}{RESET} → {WHITE}sin PTR{RESET}")

    # --- Autenticación de correo: SPF / DKIM / DMARC ------------------------
    _sub("Autenticación de correo (SPF / DKIM / DMARC)")
    txt_root = _txt_values(resolver, domain)
    spf = [t for t in txt_root if t.lower().startswith("v=spf1")]
    if spf:
        print(f"{GREEN}{'SPF'.ljust(8)}{RESET} : {spf[0]}")
        if "~all" in spf[0] or "?all" in spf[0]:
            findings.append(("BAJO", "correo", "SPF con política laxa (~all/?all): no rechaza correo falsificado, solo lo marca."))
        elif "-all" not in spf[0]:
            findings.append(("MEDIO", "correo", "SPF sin '-all' al final: no define claramente qué hacer con el resto de orígenes."))
    else:
        print(f"{YELLOW}{'SPF'.ljust(8)}{RESET} : no configurado")
        findings.append(("MEDIO", "correo", "Sin registro SPF: facilita la suplantación de remitente (phishing con el dominio)."))

    dmarc = _txt_values(resolver, f"_dmarc.{domain}")
    if dmarc:
        print(f"{GREEN}{'DMARC'.ljust(8)}{RESET} : {dmarc[0]}")
        if "p=none" in dmarc[0].lower():
            findings.append(("BAJO", "correo", "DMARC en modo 'p=none': solo reporta, no bloquea correo falsificado."))
        elif "p=reject" not in dmarc[0].lower() and "p=quarantine" not in dmarc[0].lower():
            findings.append(("BAJO", "correo", "DMARC configurado pero sin política clara de rechazo/cuarentena."))
    else:
        print(f"{YELLOW}{'DMARC'.ljust(8)}{RESET} : no configurado")
        findings.append(("MEDIO", "correo", "Sin registro DMARC: sin protección adicional contra suplantación de remitente."))

    dkim_found = []
    for sel in DKIM_SELECTORS:
        vals = _txt_values(resolver, f"{sel}._domainkey.{domain}")
        if vals:
            dkim_found.append(sel)
    if dkim_found:
        print(f"{GREEN}{'DKIM'.ljust(8)}{RESET} : selector(es) encontrados → {', '.join(dkim_found)}")
    else:
        print(f"{CYAN}{'DKIM'.ljust(8)}{RESET} : no se encontró ninguno de los selectores habituales probados "
              f"({len(DKIM_SELECTORS)}; puede usar uno no estándar)")

    # --- DNSSEC --------------------------------------------------------------
    _sub("DNSSEC")
    try:
        dnskey = resolver.resolve(domain, "DNSKEY")
        print(f"{GREEN}Zona firmada{RESET} ─ {len(dnskey)} DNSKEY publicada(s)")
    except Exception:
        print(f"{YELLOW}Zona NO firmada{RESET} (sin registros DNSKEY)")
        findings.append(("BAJO", "DNS", "DNSSEC no habilitado: las respuestas DNS no están firmadas criptográficamente."))

    # --- Transferencia de zona -----------------------------------------------
    if ns_hosts:
        try:
            _check_zone_transfer(domain, ns_hosts, findings)
        except ImportError:
            _info("dnspython no trae soporte de zona en este entorno, se omite el chequeo de AXFR.")
        except Exception as exc:
            _warn(f"No se pudo completar el chequeo de AXFR : {exc}")

    netsec._print_findings(findings)


# ---------------------------------------------------------------------------
# 5. Subdominios (fuentes públicas, sin API key)
# ---------------------------------------------------------------------------
def _src_crtsh(hostname):
    url = f"https://crt.sh/?q=%25.{hostname}&output=json"
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    data = loads(r.text)
    return {entry["name_value"] for entry in data}


def _src_hackertarget(hostname):
    url = f"https://api.hackertarget.com/hostsearch/?q={hostname}"
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    if "error" in r.text.lower() or "API count exceeded" in r.text:
        return set()
    return {line.split(",")[0] for line in r.text.splitlines() if line}


def _src_certspot(hostname):
    url = "https://api.certspotter.com/v1/issuances"
    params = {"domain": hostname, "expand": "dns_names", "include_subdomains": "true"}
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    out = set()
    for item in r.json():
        out.update(item.get("dns_names", []))
    return out


def _src_wayback(hostname):
    url = "http://web.archive.org/cdx/search/cdx"
    params = {"url": f"*.{hostname}/*", "fl": "original", "collapse": "urlkey", "limit": 50000}
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    out = set()
    for line in r.text.splitlines():
        host = line.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        if host.endswith(hostname) and host != hostname:
            out.add(host)
    return out


SUB_SOURCES = {
    "crt.sh": _src_crtsh,
    "HackerTarget": _src_hackertarget,
    "CertSpotter": _src_certspot,
    "Wayback": _src_wayback,
}

# Servicios SaaS conocidos donde un CNAME "colgado" (el servicio ya no
# tiene nada registrado para ese nombre) suele permitir que un tercero
# reclame el subdominio (subdomain takeover). Lista de fingerprints de
# dominio CNAME, no exhaustiva pero cubre los casos más comunes.
TAKEOVER_CNAME_FINGERPRINTS = (
    "github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com",
    "s3-website", "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
    "trafficmanager.net", "blob.core.windows.net", "cloudfront.net",
    "wordpress.com", "shopify.com", "myshopify.com", "surge.sh",
    "bitbucket.io", "fastly.net", "pantheonsite.io", "zendesk.com",
    "statuspage.io", "helpscoutdocs.com", "ghost.io", "readme.io",
    "unbouncepages.com", "webflow.io", "wpengine.com", "netlify.app",
    "pages.dev", "vercel.app", "firebaseapp.com", "tumblr.com",
)


def _resolve_sub(sub):
    """(ip_o_None, cname_o_None). Usa dnspython si está, si no gethostbyname."""
    cname = None
    if dns is not None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
            ans = resolver.resolve(sub, "CNAME")
            cname = ans[0].to_text().rstrip(".")
        except Exception:
            pass
    try:
        ip = socket.gethostbyname(sub)
    except Exception:
        ip = None
    return ip, cname


def mod_subdomains(tgt):
    _section("Subdominios")
    if tgt.is_ip:
        return _warn("No soportado para direcciones IP.")
    if requests is None:
        return _need("requests", "requests")

    hostname = tgt.apex or tgt.hostname
    found = set()

    _sub("Fuentes consultadas")
    with ThreadPoolExecutor(max_workers=len(SUB_SOURCES)) as pool:
        futures = {pool.submit(func, hostname): name for name, func in SUB_SOURCES.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                subs = fut.result()
                found.update(subs)
                _ok(f"{name.ljust(14)} : {len(subs)} encontrados")
            except Exception as exc:
                _err(f"{name.ljust(14)} : {exc}")

    valid = re.compile(r"^[A-Za-z0-9._-]+$")
    found = sorted(s for s in found if s.endswith(hostname) and valid.match(s))

    if not found:
        return _warn("No se encontró ningún subdominio en las fuentes consultadas.")

    # --- Detección de DNS wildcard: si un nombre inventado también resuelve,
    #     cualquier subdominio "encontrado" podría ser un falso positivo -----
    _sub("Chequeo de DNS wildcard")
    probe_name = f"osighost-wildcard-check-{random.randint(100000, 999999)}.{hostname}"
    wildcard_ip, _ = _resolve_sub(probe_name)
    if wildcard_ip:
        _warn(f"Este dominio tiene DNS wildcard (todo resuelve a {wildcard_ip}). "
              f"La lista de abajo puede incluir subdominios que no existen realmente.")
    else:
        _ok("Sin DNS wildcard detectado: los subdominios que resuelven abajo son reales.")

    # --- Resolución en paralelo: vivos vs. solo-históricos, + CNAME --------
    _sub(f"Resolviendo {len(found)} subdominios")
    resueltos, muertos, takeovers = [], [], []
    done = 0
    with ThreadPoolExecutor(max_workers=30) as pool:
        futs = {pool.submit(_resolve_sub, s): s for s in found}
        for fut in as_completed(futs):
            done += 1
            print(f"\r\033[K{CYAN}[*]{RESET} {done}/{len(found)}", end="", flush=True)
            s = futs[fut]
            ip, cname = fut.result()
            if ip:
                resueltos.append((s, ip, cname))
            else:
                muertos.append((s, cname))
                if cname and any(fp in cname.lower() for fp in TAKEOVER_CNAME_FINGERPRINTS):
                    takeovers.append((s, cname))
    print("\r\033[K", end="")

    resueltos.sort()
    print(f"\n{GREEN}[+]{RESET} Total único : {len(found)}  ·  "
          f"{GREEN}con DNS activo : {len(resueltos)}{RESET}  ·  "
          f"{CYAN}sin resolver (solo histórico/CT) : {len(muertos)}{RESET}\n")

    LIMITE = 60
    for s, ip, cname in resueltos[:LIMITE]:
        extra = f"  {CYAN}(CNAME → {cname}){RESET}" if cname else ""
        print(f"   {GREEN}{s.ljust(40)}{RESET} → {ip}{extra}")
    if len(resueltos) > LIMITE:
        _info(f"... y {len(resueltos) - LIMITE} más con DNS activo (truncado en pantalla).")

    if muertos:
        print(f"\n{WHITE}Sin resolver actualmente (pueden haber sido dados de baja){RESET}\n")
        for s, cname in muertos[:20]:
            extra = f"  {CYAN}(CNAME → {cname}){RESET}" if cname else ""
            print(f"   {CYAN}{s}{RESET}{extra}")
        if len(muertos) > 20:
            _info(f"... y {len(muertos) - 20} más sin resolver (truncado en pantalla).")

    if takeovers:
        print(f"\n{RED}❯ Posible subdomain takeover{RESET}\n")
        for s, cname in takeovers:
            print(f"   {RED}{s}{RESET} → CNAME activo hacia {cname}, pero el nombre NO resuelve "
                  f"(el servicio de destino puede estar sin reclamar)")
        _warn("Verificar manualmente antes de reportar: puede haber falsos positivos.")


# ---------------------------------------------------------------------------
# 6. Crawler (robots, sitemap, links, fingerprint de tecnología, formularios,
#    emails expuestos y comentarios HTML sospechosos; además del escaneo de
#    secretos que ya tenía)
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SUSPICIOUS_COMMENT_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX|password|contraseñ|clave|debug|backdoor|temporal)\b", re.I)

TECH_MARKERS = [
    ("WordPress",      re.compile(r"wp-content|wp-includes|/wp-json/", re.I)),
    ("Joomla",         re.compile(r"/components/com_|Joomla!", re.I)),
    ("Drupal",         re.compile(r"Drupal\.settings|/sites/default/files", re.I)),
    ("Magento",        re.compile(r"Mage\.Cookies|/skin/frontend/", re.I)),
    ("Shopify",         re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I)),
    ("React",          re.compile(r"__NEXT_DATA__|data-reactroot|react-dom", re.I)),
    ("Angular",        re.compile(r"ng-version|ng-app", re.I)),
    ("Vue.js",         re.compile(r"__vue__|data-v-[0-9a-f]{8}", re.I)),
    ("jQuery",         re.compile(r"jquery[.\-]", re.I)),
    ("Bootstrap",      re.compile(r"bootstrap(\.min)?\.css|bootstrap(\.min)?\.js", re.I)),
    ("Cloudflare",     re.compile(r"cloudflare", re.I)),
    ("Google Analytics", re.compile(r"google-analytics\.com|gtag\(|googletagmanager", re.I)),
]


def mod_crawler(tgt):
    _section("Crawler")
    if requests is None:
        return _need("requests", "requests")
    try:
        import bs4
    except ImportError:
        return _need("bs4", "beautifulsoup4 lxml")

    base = f"{tgt.protocol}://{tgt.hostname}" + (f":{tgt.port}" if tgt.port else "")

    try:
        resp = requests.get(tgt.url, headers=USER_AGENT, verify=False, timeout=TIMEOUT)
    except Exception as exc:
        return _err(f"Excepción : {exc}")
    if resp.status_code != 200:
        return _err(f"Status : {resp.status_code}")

    soup = bs4.BeautifulSoup(resp.content, "lxml")

    def probe(path):
        try:
            r = requests.get(base + path, headers=USER_AGENT, verify=False, timeout=TIMEOUT)
            return r.status_code, r.text
        except Exception:
            return None, ""

    _sub("robots.txt y sitemap")
    rb_status, rb_text = probe("/robots.txt")
    if rb_status == 200:
        lines = [l for l in rb_text.splitlines() if l.lower().startswith(("disallow", "allow", "sitemap"))]
        _ok(f"robots.txt encontrado ({len(lines)} entradas)")
        for l in lines[:15]:
            print(f"   {l.strip()}")
        if len(lines) > 15:
            _info(f"... y {len(lines) - 15} más (truncado en pantalla).")
    else:
        _warn("robots.txt no encontrado")

    sm_status, sm_text = probe("/sitemap.xml")
    if sm_status == 200:
        n_urls = sm_text.count("<loc>")
        _ok(f"sitemap.xml encontrado (~{n_urls} URLs listadas)" if n_urls else "sitemap.xml encontrado")
    else:
        _warn("sitemap.xml no encontrado")

    css = {l.get("href") for l in soup.find_all("link", href=True) if ".css" in (l.get("href") or "")}
    js = {s.get("src") for s in soup.find_all("script", src=True) if s.get("src")}
    imgs = {i.get("src") for i in soup.find_all("img", src=True) if i.get("src")}

    domain = tgt.apex or tgt.hostname
    links = {a.get("href") for a in soup.find_all("a", href=True)}
    internal = {l for l in links if domain in l}
    external = sorted(l for l in links if domain not in l and l.startswith("http"))

    title = soup.title.string.strip() if soup.title and soup.title.string else "(sin título)"
    meta_desc = ""
    meta_gen = ""
    for m in soup.find_all("meta"):
        name = (m.get("name") or "").lower()
        if name == "description":
            meta_desc = (m.get("content") or "").strip()
        elif name == "generator":
            meta_gen = (m.get("content") or "").strip()

    _sub("Información general")
    print(f"{WHITE}Título{RESET}            : {title}")
    print(f"{WHITE}Meta descripción{RESET}  : {meta_desc or '(sin descripción)'}")
    if meta_gen:
        print(f"{WHITE}Generador{RESET}         : {meta_gen}")
    print(f"{WHITE}Server{RESET}            : {resp.headers.get('Server', 'no informado')}")
    if resp.headers.get("X-Powered-By"):
        print(f"{WHITE}X-Powered-By{RESET}      : {resp.headers['X-Powered-By']}")
    print(f"{WHITE}CSS{RESET}               : {len(css)}")
    print(f"{WHITE}JavaScript{RESET}        : {len(js)}")
    print(f"{WHITE}Imágenes{RESET}          : {len(imgs)}")
    print(f"{WHITE}Enlaces internos{RESET}  : {len(internal)}")
    print(f"{WHITE}Enlaces externos{RESET}  : {len(external)}")

    # --- Fingerprint de tecnología (CMS/framework/librerías) ---------------
    _sub("Tecnologías detectadas")
    haystack = resp.text + " " + " ".join(css | js) + " " + meta_gen
    detectadas = [name for name, pattern in TECH_MARKERS if pattern.search(haystack)]
    if detectadas:
        for t in detectadas:
            print(f"   {GREEN}✓{RESET} {t}")
    else:
        _info("No se reconoció ninguna tecnología de la lista de huellas probada.")

    # --- Dominios externos a los que se referencia --------------------------
    if external:
        _sub("Dominios externos referenciados")
        conteo = {}
        for l in external:
            try:
                host = urlparse(l).netloc
            except Exception:
                host = l
            conteo[host] = conteo.get(host, 0) + 1
        for host, n in sorted(conteo.items(), key=lambda kv: -kv[1])[:15]:
            print(f"   {CYAN}{host.ljust(32)}{RESET} ×{n}")
        if len(conteo) > 15:
            _info(f"... y {len(conteo) - 15} dominios externos más.")

    # --- Formularios: dónde envían datos y si hay señales de riesgo --------
    forms = soup.find_all("form")
    if forms:
        _sub(f"Formularios encontrados ({len(forms)})")
        for f in forms[:10]:
            action = f.get("action") or "(mismo URL)"
            method = (f.get("method") or "GET").upper()
            has_pw = bool(f.find("input", {"type": "password"}))
            has_csrf = any(
                "csrf" in (i.get("name") or "").lower() or "token" in (i.get("name") or "").lower()
                for i in f.find_all("input", {"type": "hidden"})
            )
            flags = []
            if has_pw and tgt.protocol != "https":
                flags.append(f"{RED}contraseña sobre HTTP sin cifrar{RESET}")
            if method == "GET" and has_pw:
                flags.append(f"{RED}envía credenciales por GET (quedan en logs/URL){RESET}")
            if has_pw and not has_csrf:
                flags.append(f"{YELLOW}sin campo que parezca token CSRF{RESET}")
            tag = f"  ─ {' · '.join(flags)}" if flags else ""
            print(f"   {WHITE}{method.ljust(5)}{RESET} → {action}{tag}")
        if len(forms) > 10:
            _info(f"... y {len(forms) - 10} formularios más (truncado en pantalla).")

    # --- Emails expuestos en el HTML ---------------------------------------
    emails = sorted(set(EMAIL_RE.findall(resp.text)))
    if emails:
        _sub(f"Direcciones de email expuestas ({len(emails)})")
        for e in emails[:15]:
            print(f"   {YELLOW}{e}{RESET}")
        if len(emails) > 15:
            _info(f"... y {len(emails) - 15} más (truncado en pantalla).")

    # --- Comentarios HTML con palabras sospechosas --------------------------
    comments = soup.find_all(string=lambda t: isinstance(t, bs4.Comment))
    sospechosos = [c.strip() for c in comments if SUSPICIOUS_COMMENT_RE.search(c)]
    if sospechosos:
        _sub(f"Comentarios HTML sospechosos ({len(sospechosos)})")
        for c in sospechosos[:10]:
            texto = c if len(c) <= 100 else c[:100] + "…"
            print(f"   {YELLOW}{texto}{RESET}")

    # Mismo JS que ya se detectó arriba: ahora se analiza buscando
    # patrones de secretos/API keys expuestas (no solo se cuenta).
    _sub("Secretos / API Keys expuestas")
    js_abs = {js_url if js_url.startswith("http") else requests.compat.urljoin(base, js_url) for js_url in js if js_url}
    hits = netsec.find_secrets_in_page_and_js(resp.text, tgt.url, js_abs)
    if hits:
        for name, source, masked in hits:
            print(f"   {RED}{name.ljust(28)}{RESET} {masked}  {CYAN}({source}){RESET}")
        _warn("Verificar manualmente: puede haber falsos positivos.")
    else:
        _ok("No se encontraron patrones de secretos en lo analizado.")


# ---------------------------------------------------------------------------
# 7. Fuerza de directorios
# ---------------------------------------------------------------------------
def mod_dirsearch(tgt, wordlist=WORDLIST_PATH, threads=20, extensions=""):
    _section("Fuerza de Directorios")
    if requests is None:
        return _need("requests", "requests")
    if not os.path.exists(wordlist):
        return _err(f"No se encontró el wordlist : {wordlist}")

    with open(wordlist, "r", errors="replace") as f:
        words = [w.strip() for w in f if w.strip()]

    exts = [e.strip() for e in extensions.split(",") if e.strip()] if extensions else [""]
    base = tgt.url

    paths = []
    for w in words:
        for e in exts:
            paths.append(f"/{w}.{e}" if e else f"/{w}")

    _info(f"Probando {len(paths)} rutas con {threads} hilos...")

    def probe(path):
        try:
            r = requests.get(base + path, headers=USER_AGENT, verify=False, timeout=6, allow_redirects=False)
            return path, r.status_code, len(r.content)
        except Exception:
            return path, None, None

    found = []
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for path, status, length in pool.map(probe, paths):
            done += 1
            print(f"\r\033[K{CYAN}[*]{RESET} {done}/{len(paths)}", end="", flush=True)
            if status is None:
                continue
            if status == 200:
                found.append((path, status, length))
                print(f"\r\033[K{GREEN}{status}{RESET}  {str(length).ljust(8)} {path}")
            elif status in (301, 302, 403):
                found.append((path, status, length))
                color = YELLOW if status != 403 else RED
                print(f"\r\033[K{color}{status}{RESET}  {str(length).ljust(8)} {path}")

    print(f"\n\n{GREEN}[+]{RESET} Encontrados : {len(found)}")

    # Además del wordlist genérico: una lista puntual de archivos de
    # configuración/credenciales que suelen quedar expuestos por error.
    print(f"\n{WHITE}❯ Archivos Sensibles{RESET}\n")
    sensibles = netsec.probe_sensitive_files(base)
    if sensibles:
        for path, status, length, critico in sensibles:
            color = RED if critico else YELLOW
            tag = " ⚠ CRÍTICO" if critico else ""
            print(f"   {color}{status}{RESET}  {str(length).ljust(8)} /{path}{color}{tag}{RESET}")
    else:
        _ok("No se encontraron archivos sensibles de la lista probada.")


# ---------------------------------------------------------------------------
# 8. Wayback Machine (URLs históricas + triage)
# ---------------------------------------------------------------------------
JUICY_EXT = {"js", "json", "xml", "env", "config", "bak", "backup", "old", "sql", "db", "log", "zip", "key", "pem"}
JUICY_PATHS = re.compile(r"/(admin|api|v\d+|graphql|internal|debug|swagger|backup|config|dashboard)(/|$|\?)", re.I)
JUICY_PARAMS = re.compile(r"[?&](url|redirect|next|return|goto|dest|file|path|id|cmd|exec|token|key|secret|src)=", re.I)


def mod_wayback(tgt):
    _section("Wayback Machine")
    if requests is None:
        return _need("requests", "requests")

    domain = tgt.apex or tgt.hostname
    url = "http://web.archive.org/cdx/search/cdx"
    params = {"url": f"{domain}/*", "fl": "original", "collapse": "urlkey", "limit": 50000}

    try:
        r = requests.get(url, params=params, timeout=30)
    except Exception as exc:
        return _err(f"Excepción : {exc}")
    if r.status_code != 200:
        return _err(f"Status : {r.status_code}")

    urls = [u for u in set(r.text.splitlines()) if u.startswith("http")]
    js_files, api_eps, juicy_paths, juicy_params, juicy_ext = [], [], [], [], {}

    for u in urls:
        parsed = urlparse(u)
        path = parsed.path.lower()
        ext = path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
        if ext in JUICY_EXT:
            juicy_ext.setdefault(ext, []).append(u)
        if ext == "js":
            js_files.append(u)
        if re.search(r"/api/|/graphql|/v\d+", path):
            api_eps.append(u)
        elif JUICY_PATHS.search(path):
            juicy_paths.append(u)
        if parsed.query and JUICY_PARAMS.search("?" + parsed.query):
            juicy_params.append(u)

    print(f"{WHITE}Total URLs{RESET}          : {len(urls)}")
    print(f"{WHITE}Archivos JS{RESET}         : {len(js_files)}")
    print(f"{WHITE}Endpoints API{RESET}       : {len(api_eps)}")
    print(f"{WHITE}Rutas interesantes{RESET}  : {len(juicy_paths)}")
    print(f"{WHITE}Params interesantes{RESET} : {len(juicy_params)}")

    if juicy_ext:
        resumen = ", ".join(f"{e}({len(v)})" for e, v in sorted(juicy_ext.items()))
        print(f"\n{YELLOW}Extensiones sensibles{RESET} : {resumen}")

    if juicy_params:
        print(f"\n{YELLOW}Parámetros a revisar{RESET} :")
        for u in juicy_params[:8]:
            print(f"   {u}")
