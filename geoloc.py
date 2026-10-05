# -*- coding: utf-8 -*-
"""
OSIGhost - Módulo de GEOLOCALIZACIÓN (opción 2 del menú principal)

Geolocalización de ACTIVOS y EVIDENCIA del cliente, siempre dentro del alcance
del contrato:

  - IP / dominio ........ ubicación aproximada, ASN, proveedor, VPN/proxy/hosting
  - Lote de IPs ......... archivo o logs del cliente -> resumen por país / ASN
  - Infraestructura ..... A / AAAA / MX / NS de un dominio, geolocalizados
  - Metadatos ........... EXIF (GPS, cámara), Office (autor, empresa), PDF
  - Teléfono ............ solo datos del PLAN DE NUMERACIÓN (país, zona, tipo,
                          operadora original). NO ubica al titular ni al equipo.
  - Exportar ............ mapa HTML (Leaflet) + CSV de todo lo consultado

Lo que NO hace, a propósito: ubicar personas por DNI, ni ubicar al titular de
una línea telefónica. Los datos personales que aparezcan en el relevamiento
quedan sujetos a la Ley 25.326.
"""

import csv
import datetime
import html
import ipaddress
import json
import os
import re
import socket
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    Image = None

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as pn_timezone
except ImportError:
    phonenumbers = None

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

from osighost import RED, WHITE, RESET, GREEN, YELLOW, CYAN

HERE = os.path.dirname(os.path.realpath(__file__))
OUT_DIR = os.path.join(HERE, "reportes", "geolocalizacion")
USER_AGENT = {"User-Agent": "OSIGhost/1.0"}
TIMEOUT = 8

IPAPI_FIELDS = ("status,message,country,countryCode,regionName,city,zip,lat,lon,"
                "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")

# Todo lo consultado en la sesión (para exportar mapa / CSV)
SESSION_ROWS = []


# ---------------------------------------------------------------------------
# Helpers de impresión
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


def _kv(label, value, width=20):
    print(f"   {WHITE}{label.ljust(width)}{RESET}: {value}")


def _need(pip_name):
    _err(f"Falta el módulo '{pip_name}'. Instalá dependencias: pip install -r requirements.txt")


def _pedir(texto, tag):
    print(f"\n{WHITE}{texto}{RESET}")
    try:
        return input(f"{RED}{tag}{WHITE} > {RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        return None


def _limpiar_host(raw):
    return raw.split("://")[-1].split("/")[0].split(":")[0].strip()


def _pedir_paises():
    """Lista de países esperados para el negocio (códigos ISO, ej: AR,UY,US)."""
    raw = _pedir("Países ESPERADOS para el negocio, códigos ISO separados por coma "
                 "(ej: AR,US). ENTER = no comparar", "PAISES")
    if not raw:
        return set()
    return {p.strip().upper() for p in re.split(r"[,\s;]+", raw) if p.strip()}


def _es_publica(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Núcleo: consulta de IP
# ---------------------------------------------------------------------------
def _norm_ipwho(d, ip):
    conn = d.get("connection") or {}
    tz = d.get("timezone") or {}
    return {
        "query": ip, "status": "success", "fuente": "ipwho.is",
        "country": d.get("country"), "countryCode": d.get("country_code"),
        "regionName": d.get("region"), "city": d.get("city"), "zip": d.get("postal"),
        "lat": d.get("latitude"), "lon": d.get("longitude"),
        "timezone": tz.get("id"), "isp": conn.get("isp"), "org": conn.get("org"),
        "as": f"AS{conn.get('asn')}" if conn.get("asn") else None,
        "asname": conn.get("org"), "reverse": None,
        "mobile": None, "proxy": None, "hosting": None,
    }


def lookup_ip(ip):
    """Devuelve un dict normalizado (ip-api.com primero, ipwho.is de respaldo)."""
    if requests is None:
        return {"query": ip, "status": "fail", "message": "falta 'requests'"}
    if not _es_publica(ip):
        return {"query": ip, "status": "fail", "message": "IP privada/reservada: no es geolocalizable"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", params={"fields": IPAPI_FIELDS},
                         headers=USER_AGENT, timeout=TIMEOUT)
        d = r.json()
        if d.get("status") == "success":
            d["fuente"] = "ip-api.com"
            return d
    except Exception:
        pass
    try:
        r = requests.get(f"https://ipwho.is/{ip}", headers=USER_AGENT, timeout=TIMEOUT)
        d = r.json()
        if d.get("success"):
            return _norm_ipwho(d, ip)
    except Exception:
        pass
    return {"query": ip, "status": "fail", "message": "sin respuesta de los servicios de geolocalización"}


def lookup_batch(ips):
    """Geolocaliza muchas IPs. Usa el endpoint batch de ip-api (100 por pedido)
    y cae a consulta individual en paralelo si algo falla."""
    res = {}
    publicas = [ip for ip in ips if _es_publica(ip)]
    for ip in ips:
        if ip not in publicas:
            res[ip] = {"query": ip, "status": "fail", "message": "IP privada/reservada"}
    if requests is None:
        return res

    pendientes = []
    for i in range(0, len(publicas), 100):
        chunk = publicas[i:i + 100]
        try:
            r = requests.post("http://ip-api.com/batch", params={"fields": IPAPI_FIELDS},
                              data=json.dumps([{"query": ip} for ip in chunk]),
                              headers=USER_AGENT, timeout=20)
            for d in r.json():
                if d.get("status") == "success":
                    d["fuente"] = "ip-api.com"
                    res[d["query"]] = d
            pendientes += [ip for ip in chunk if ip not in res]
        except Exception:
            pendientes += chunk

    if pendientes:
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(lookup_ip, ip): ip for ip in pendientes}
            for f in as_completed(futs):
                res[futs[f]] = f.result()
    return res


def _registrar_ip(d, origen=""):
    if d.get("status") != "success":
        return
    SESSION_ROWS.append({
        "tipo": "IP", "etiqueta": d.get("query"), "origen": origen,
        "pais": d.get("country"), "codigo_pais": d.get("countryCode"),
        "region": d.get("regionName"), "ciudad": d.get("city"),
        "lat": d.get("lat"), "lon": d.get("lon"),
        "asn": d.get("as"), "organizacion": d.get("org") or d.get("isp"),
        "vpn_proxy": d.get("proxy"), "hosting": d.get("hosting"),
    })


def _flags(d):
    f = []
    if d.get("proxy"):
        f.append("VPN/Proxy/Tor")
    if d.get("hosting"):
        f.append("Hosting/Datacenter")
    if d.get("mobile"):
        f.append("Red móvil")
    return f


def _print_ip(d):
    if d.get("status") != "success":
        _err(f"{d.get('query')} : {d.get('message', 'sin datos')}")
        return
    print(f"\n{WHITE}❯ {d['query']}{RESET}")
    ubic = ", ".join(x for x in (d.get("city"), d.get("regionName"), d.get("country")) if x)
    _kv("Ubicación aprox.", ubic or "-")
    if d.get("lat") is not None:
        _kv("Coordenadas", f"{d['lat']}, {d['lon']}   (https://www.openstreetmap.org/?mlat={d['lat']}&mlon={d['lon']}#map=10/{d['lat']}/{d['lon']})")
    _kv("Zona horaria", d.get("timezone") or "-")
    _kv("ASN", d.get("as") or "-")
    _kv("Organización / ISP", d.get("org") or d.get("isp") or "-")
    if d.get("reverse"):
        _kv("DNS inverso", d["reverse"])
    flags = _flags(d)
    _kv("Tipo de red", ", ".join(flags) if flags else "residencial / corporativa (sin marcas)")
    _kv("Fuente", d.get("fuente", "-"))
    if d.get("proxy") or d.get("hosting"):
        _warn("La IP pertenece a VPN/proxy/datacenter: la ubicación es la del servicio, "
              "NO la del usuario real.")
    else:
        _info("La geolocalización por IP es aproximada (nivel ciudad/región), nunca un domicilio.")


# ---------------------------------------------------------------------------
# 1. IP o dominio
# ---------------------------------------------------------------------------
def mod_ip_dominio(objetivo):
    _section("GEOLOCALIZACIÓN DE IP / DOMINIO")
    if requests is None:
        _need("requests")
        return
    host = _limpiar_host(objetivo)
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            _err(f"No se pudo resolver {host}: {exc}")
            return
        ips = sorted({i[4][0] for i in infos})
        _info(f"{host} resuelve a {len(ips)} IP(s): {', '.join(ips)}")

    for ip in ips:
        d = lookup_ip(ip)
        _print_ip(d)
        _registrar_ip(d, origen=host)


# ---------------------------------------------------------------------------
# 2. Lote de IPs (archivo / logs)
# ---------------------------------------------------------------------------
_RE_CANDIDATO = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+")


def extraer_ips(texto):
    """Devuelve Counter {ip: apariciones} con todas las IPs válidas del texto."""
    c = Counter()
    for m in _RE_CANDIDATO.findall(texto):
        try:
            c[str(ipaddress.ip_address(m))] += 1
        except ValueError:
            continue
    return c


def mod_lote_ips(ruta, esperados=None):
    _section("GEOLOCALIZACIÓN POR LOTE DE IPs")
    if requests is None:
        _need("requests")
        return
    ruta = os.path.expanduser(ruta.strip().strip('"').strip("'"))
    if not os.path.isfile(ruta):
        _err(f"No existe el archivo: {ruta}")
        return
    with open(ruta, "r", encoding="utf-8", errors="ignore") as fh:
        conteo = extraer_ips(fh.read())
    if not conteo:
        _warn("No se encontraron direcciones IP en el archivo.")
        return
    publicas = [ip for ip in conteo if _es_publica(ip)]
    _info(f"{len(conteo)} IP(s) únicas encontradas · {len(publicas)} públicas · "
          f"{len(conteo) - len(publicas)} privadas/reservadas (se omiten)")
    if not publicas:
        return

    _info("Consultando geolocalización...")
    datos = lookup_batch(publicas)
    ok = {ip: d for ip, d in datos.items() if d.get("status") == "success"}
    fallidas = [ip for ip in publicas if ip not in ok]
    for d in ok.values():
        _registrar_ip(d, origen=os.path.basename(ruta))

    por_pais, por_asn = Counter(), Counter()
    nube = []
    for ip, d in ok.items():
        peso = conteo[ip]
        por_pais[f"{d.get('country')} ({d.get('countryCode')})"] += peso
        por_asn[f"{d.get('as') or '?'} · {d.get('org') or d.get('isp') or '?'}"] += peso
        if d.get("proxy") or d.get("hosting"):
            nube.append(ip)

    _section("RESUMEN POR PAÍS (apariciones en el archivo)")
    for pais, n in por_pais.most_common(15):
        print(f"   {WHITE}{str(n).rjust(7)}{RESET}  {pais}")
    _section("TOP ASN / PROVEEDORES")
    for asn, n in por_asn.most_common(10):
        print(f"   {WHITE}{str(n).rjust(7)}{RESET}  {asn}")

    if nube:
        _warn(f"{len(nube)} IP(s) son VPN/proxy/hosting (origen real enmascarado): "
              + ", ".join(nube[:8]) + ("..." if len(nube) > 8 else ""))
    if esperados:
        fuera = [(ip, d) for ip, d in ok.items() if d.get("countryCode") not in esperados]
        _section(f"FUERA DE LOS PAÍSES ESPERADOS ({', '.join(sorted(esperados))})")
        if not fuera:
            _ok("Todo el tráfico proviene de países esperados.")
        else:
            _warn(f"{len(fuera)} IP(s) fuera de lo esperado:")
            for ip, d in sorted(fuera, key=lambda x: -conteo[x[0]])[:25]:
                print(f"   {YELLOW}{ip.ljust(40)}{RESET} {str(conteo[ip]).rjust(5)}x  "
                      f"{d.get('country')} · {d.get('org') or d.get('isp') or '-'}")
    if fallidas:
        _warn(f"{len(fallidas)} IP(s) sin datos de geolocalización.")
    _info("Podés exportar mapa y CSV con la opción 'Exportar mapa y CSV'.")


# ---------------------------------------------------------------------------
# 3. Infraestructura de un dominio (A / AAAA / MX / NS)
# ---------------------------------------------------------------------------
def _resolver_nombres(nombres):
    res = {}
    for n in nombres:
        try:
            res[n] = sorted({i[4][0] for i in socket.getaddrinfo(n, None)})
        except socket.gaierror:
            res[n] = []
    return res


def mod_infraestructura(dominio, esperados=None):
    _section("GEOLOCALIZACIÓN DE INFRAESTRUCTURA DEL DOMINIO")
    if requests is None:
        _need("requests")
        return
    dom = _limpiar_host(dominio)
    grupos = {"Web (A/AAAA)": [dom, "www." + dom]}
    if dns is not None:
        for tipo, etiqueta in (("MX", "Correo (MX)"), ("NS", "DNS (NS)")):
            try:
                resp = dns.resolver.resolve(dom, tipo, lifetime=6)
                nombres = []
                for r in resp:
                    t = str(r.exchange if tipo == "MX" else r.target).rstrip(".")
                    nombres.append(t)
                grupos[etiqueta] = sorted(set(nombres))
            except Exception:
                grupos[etiqueta] = []
    else:
        _warn("Sin dnspython: solo se analiza A/AAAA (MX y NS requieren 'dnspython').")

    todas = set()
    mapa = {}
    for etiqueta, nombres in grupos.items():
        mapa[etiqueta] = _resolver_nombres(nombres)
        for ips in mapa[etiqueta].values():
            todas.update(ips)
    datos = lookup_batch(sorted(todas)) if todas else {}

    fuera = []
    for etiqueta, resueltos in mapa.items():
        print(f"\n{WHITE}❯ {etiqueta}{RESET}\n")
        if not any(resueltos.values()):
            print(f"   {YELLOW}(sin registros){RESET}")
            continue
        for nombre, ips in resueltos.items():
            for ip in ips:
                d = datos.get(ip, {})
                if d.get("status") == "success":
                    _registrar_ip(d, origen=f"{dom} · {etiqueta} · {nombre}")
                    extra = f" [{', '.join(_flags(d))}]" if _flags(d) else ""
                    print(f"   {nombre.ljust(32)} {ip.ljust(40)} {d.get('city') or '-'}, "
                          f"{d.get('country')} · {d.get('org') or d.get('isp') or '-'}{extra}")
                    if esperados and d.get("countryCode") not in esperados:
                        fuera.append((nombre, ip, d))
                else:
                    print(f"   {nombre.ljust(32)} {ip.ljust(40)} {YELLOW}{d.get('message', 'sin datos')}{RESET}")

    if esperados:
        _section("CONTROL DE PAÍSES")
        if fuera:
            for nombre, ip, d in fuera:
                _warn(f"{nombre} ({ip}) está en {d.get('country')}: fuera de {', '.join(sorted(esperados))}")
            _info("Hallazgo para el informe: infraestructura alojada fuera de la jurisdicción esperada "
                  "(revisar cláusulas de residencia de datos).")
        else:
            _ok("Toda la infraestructura analizada está en países esperados.")


# ---------------------------------------------------------------------------
# 4. Metadatos de archivos / imágenes
# ---------------------------------------------------------------------------
IMG_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"}
OFFICE_EXT = {".docx", ".xlsx", ".pptx"}
PDF_EXT = {".pdf"}
SOPORTADAS = IMG_EXT | OFFICE_EXT | PDF_EXT


def _dms_a_decimal(dms, ref):
    try:
        g, m, s = (float(x) for x in dms)
        val = g + m / 60 + s / 3600
        return -val if ref in ("S", "W") else val
    except Exception:
        return None


def _meta_imagen(ruta):
    meta = {}
    if Image is None:
        meta["_error"] = "falta Pillow"
        return meta
    with Image.open(ruta) as img:
        meta["Dimensiones"] = f"{img.width}x{img.height}"
        exif = img.getexif()
        if not exif:
            return meta
        base = {TAGS.get(k, k): v for k, v in exif.items()}
        try:
            base.update({TAGS.get(k, k): v for k, v in exif.get_ifd(0x8769).items()})
        except Exception:
            pass
        for clave in ("Make", "Model", "Software", "DateTimeOriginal", "DateTime",
                      "LensModel", "Artist", "Copyright", "HostComputer"):
            if base.get(clave):
                meta[clave] = str(base[clave]).strip("\x00 ")
        try:
            gps_raw = exif.get_ifd(0x8825)
        except Exception:
            gps_raw = {}
        gps = {GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
        if gps.get("GPSLatitude") and gps.get("GPSLongitude"):
            lat = _dms_a_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
            lon = _dms_a_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
            if lat is not None and lon is not None:
                meta["_lat"], meta["_lon"] = round(lat, 6), round(lon, 6)
                if gps.get("GPSAltitude") is not None:
                    try:
                        meta["Altitud (m)"] = round(float(gps["GPSAltitude"]), 1)
                    except Exception:
                        pass
    return meta


def _meta_office(ruta):
    meta = {}
    with zipfile.ZipFile(ruta) as z:
        for nombre, mapa in (
            ("docProps/core.xml", {"creator": "Autor", "lastModifiedBy": "Última modif. por",
                                   "created": "Creado", "modified": "Modificado",
                                   "title": "Título", "subject": "Asunto", "keywords": "Palabras clave"}),
            ("docProps/app.xml", {"Company": "Empresa", "Manager": "Responsable",
                                  "Application": "Aplicación", "AppVersion": "Versión app"}),
        ):
            if nombre not in z.namelist():
                continue
            try:
                root = ET.fromstring(z.read(nombre))
            except ET.ParseError:
                continue
            for el in root.iter():
                tag = el.tag.split("}")[-1]
                if tag in mapa and el.text and el.text.strip():
                    meta[mapa[tag]] = el.text.strip()
        rutas_int = [n for n in z.namelist() if n.lower().endswith((".jpg", ".jpeg", ".png"))]
        if rutas_int:
            meta["Imágenes embebidas"] = len(rutas_int)
    return meta


def _meta_pdf(ruta):
    meta = {}
    etiquetas = {"/Author": "Autor", "/Creator": "Creado con", "/Producer": "Productor",
                 "/Title": "Título", "/CreationDate": "Creado", "/ModDate": "Modificado"}
    if PdfReader is not None:
        info = PdfReader(ruta).metadata or {}
        for k, etq in etiquetas.items():
            v = info.get(k)
            if v:
                meta[etq] = str(v)
        return meta
    with open(ruta, "rb") as fh:
        crudo = fh.read(2_000_000)
    for k, etq in etiquetas.items():
        m = re.search(re.escape(k.encode()) + rb"\s*\(([^)]{1,200})\)", crudo)
        if m:
            meta[etq] = m.group(1).decode("latin-1", "ignore")
    return meta


def analizar_archivo(ruta):
    """Devuelve (meta, hallazgos). Las claves que empiezan con '_' son internas."""
    ext = os.path.splitext(ruta)[1].lower()
    try:
        if ext in IMG_EXT:
            meta = _meta_imagen(ruta)
        elif ext in OFFICE_EXT:
            meta = _meta_office(ruta)
        elif ext in PDF_EXT:
            meta = _meta_pdf(ruta)
        else:
            return {}, [("INFO", "Formato no soportado")]
    except Exception as exc:
        return {}, [("INFO", f"No se pudo leer: {exc}")]

    hall = []
    if "_lat" in meta:
        hall.append(("ALTO", "Coordenadas GPS embebidas: revela dónde se tomó la imagen"))
    for clave in ("Autor", "Última modif. por", "Artist"):
        if meta.get(clave):
            hall.append(("MEDIO", f"Nombre de persona/usuario en metadatos ({clave}: {meta[clave]})"))
    for clave in ("Empresa", "Responsable", "HostComputer"):
        if meta.get(clave):
            hall.append(("BAJO", f"Dato interno expuesto ({clave}: {meta[clave]})"))
    for clave in ("Make", "Model", "Software", "Creado con", "Aplicación"):
        if meta.get(clave):
            hall.append(("BAJO", f"Software/dispositivo identificable ({clave}: {meta[clave]})"))
            break
    return meta, hall


_COLOR_SEV = {"ALTO": RED, "MEDIO": YELLOW, "BAJO": CYAN, "INFO": WHITE}


def _print_archivo(ruta, meta, hall):
    print(f"\n{WHITE}❯ {ruta}{RESET}")
    visibles = {k: v for k, v in meta.items() if not k.startswith("_")}
    if not visibles and "_lat" not in meta:
        print(f"   {GREEN}(sin metadatos relevantes){RESET}")
    for k, v in visibles.items():
        _kv(k, v)
    if "_lat" in meta:
        la, lo = meta["_lat"], meta["_lon"]
        _kv("GPS", f"{la}, {lo}   (https://www.openstreetmap.org/?mlat={la}&mlon={lo}#map=16/{la}/{lo})")
    for sev, txt in hall:
        print(f"   {_COLOR_SEV.get(sev, WHITE)}[{sev}]{RESET} {txt}")


def _registrar_archivo(ruta, meta):
    SESSION_ROWS.append({
        "tipo": "ARCHIVO", "etiqueta": os.path.basename(ruta), "origen": ruta,
        "pais": "", "codigo_pais": "", "region": "", "ciudad": "",
        "lat": meta.get("_lat"), "lon": meta.get("_lon"),
        "asn": "", "organizacion": meta.get("Empresa") or meta.get("Autor") or "",
        "vpn_proxy": "", "hosting": "",
    })


def mod_metadatos(ruta):
    _section("METADATOS DE ARCHIVO / IMAGEN")
    ruta = os.path.expanduser(ruta.strip().strip('"').strip("'"))
    if not os.path.isfile(ruta):
        _err(f"No existe el archivo: {ruta}")
        return
    meta, hall = analizar_archivo(ruta)
    _print_archivo(ruta, meta, hall)
    _registrar_archivo(ruta, meta)
    if hall and any(s in ("ALTO", "MEDIO") for s, _ in hall):
        _info("Recomendación: limpiar metadatos antes de publicar (exiftool -all= / "
              "'Inspeccionar documento' en Office).")


def mod_metadatos_carpeta(carpeta):
    _section("METADATOS DE CARPETA (recursivo)")
    carpeta = os.path.expanduser(carpeta.strip().strip('"').strip("'"))
    if not os.path.isdir(carpeta):
        _err(f"No existe la carpeta: {carpeta}")
        return
    archivos = []
    for base, _, nombres in os.walk(carpeta):
        for n in nombres:
            if os.path.splitext(n)[1].lower() in SOPORTADAS:
                archivos.append(os.path.join(base, n))
    if not archivos:
        _warn("No hay imágenes, PDFs ni documentos Office en esa carpeta.")
        return
    _info(f"{len(archivos)} archivo(s) analizables encontrados.")

    con_gps, con_autor, sev_total = 0, 0, Counter()
    autores = Counter()
    for ruta in sorted(archivos):
        meta, hall = analizar_archivo(ruta)
        if hall:
            _print_archivo(ruta, meta, hall)
        _registrar_archivo(ruta, meta)
        if "_lat" in meta:
            con_gps += 1
        for k in ("Autor", "Última modif. por", "Artist"):
            if meta.get(k):
                autores[meta[k]] += 1
        if any(s == "MEDIO" for s, _ in hall):
            con_autor += 1
        for s, _ in hall:
            sev_total[s] += 1

    _section("RESUMEN")
    _kv("Archivos analizados", len(archivos))
    _kv("Con GPS embebido", f"{RED if con_gps else GREEN}{con_gps}{RESET}")
    _kv("Con nombre de persona", f"{YELLOW if con_autor else GREEN}{con_autor}{RESET}")
    if autores:
        print(f"\n   {WHITE}Nombres/usuarios más frecuentes:{RESET}")
        for nombre, n in autores.most_common(8):
            print(f"      {str(n).rjust(4)}x  {nombre}")
    if con_gps:
        _warn("Hallazgo ALTO: hay archivos que filtran coordenadas. Se pueden ver en el mapa exportado.")


# ---------------------------------------------------------------------------
# 5. Teléfono: SOLO datos del plan de numeración
# ---------------------------------------------------------------------------
_TIPOS_TEL = {}


def _tipo_tel(t):
    if not _TIPOS_TEL and phonenumbers:
        T = phonenumbers.PhoneNumberType
        _TIPOS_TEL.update({
            T.MOBILE: "Móvil", T.FIXED_LINE: "Fijo", T.FIXED_LINE_OR_MOBILE: "Fijo o móvil",
            T.TOLL_FREE: "Gratuito (0800)", T.PREMIUM_RATE: "Tarifa premium",
            T.SHARED_COST: "Costo compartido", T.VOIP: "VoIP", T.PERSONAL_NUMBER: "Personal",
            T.PAGER: "Pager", T.UAN: "Número universal", T.VOICEMAIL: "Buzón de voz",
            T.UNKNOWN: "Desconocido",
        })
    return _TIPOS_TEL.get(t, "Desconocido")


def mod_telefono(entrada, region_defecto="AR"):
    _section("TELÉFONO - DATOS DEL PLAN DE NUMERACIÓN")
    if phonenumbers is None:
        _need("phonenumbers")
        return
    entrada = entrada.strip().strip('"').strip("'")
    if os.path.isfile(os.path.expanduser(entrada)):
        with open(os.path.expanduser(entrada), "r", encoding="utf-8", errors="ignore") as fh:
            numeros = [l.strip() for l in fh if l.strip()]
    else:
        numeros = [n.strip() for n in re.split(r"[;\n]+", entrada) if n.strip()]
    if not numeros:
        _warn("No ingresaste ningún número.")
        return

    _info("Esto informa a qué país/zona/operadora fue asignada la numeración. "
          "NO ubica al titular ni al dispositivo.")
    for crudo in numeros[:200]:
        try:
            n = phonenumbers.parse(crudo, None if crudo.startswith("+") else region_defecto)
        except phonenumbers.NumberParseException as exc:
            print(f"\n{WHITE}❯ {crudo}{RESET}")
            _err(f"No se pudo interpretar: {exc}")
            continue
        valido = phonenumbers.is_valid_number(n)
        zona = geocoder.description_for_number(n, "es")
        pais = geocoder.country_name_for_number(n, "es")
        oper = carrier.name_for_number(n, "es")
        tipo = _tipo_tel(phonenumbers.number_type(n))
        tz = ", ".join(pn_timezone.time_zones_for_number(n))
        print(f"\n{WHITE}❯ {phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}{RESET}")
        _kv("Formato válido", f"{GREEN}sí{RESET}" if valido else f"{YELLOW}no{RESET}")
        _kv("País", pais or "-")
        _kv("Zona de numeración", zona or "-")
        _kv("Tipo de línea", tipo)
        _kv("Operadora original", oper or "no disponible")
        _kv("Zona(s) horaria(s)", tz or "-")
        regiones = phonenumbers.region_code_for_number(n)
        SESSION_ROWS.append({
            "tipo": "TELEFONO", "etiqueta": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164),
            "origen": "plan de numeración", "pais": pais, "codigo_pais": regiones or "",
            "region": zona, "ciudad": "", "lat": None, "lon": None,
            "asn": "", "organizacion": oper, "vpn_proxy": "", "hosting": "",
        })
    _info("La operadora mostrada es la original: con portabilidad numérica puede haber cambiado.")


# ---------------------------------------------------------------------------
# 6. Exportación: mapa Leaflet + CSV
# ---------------------------------------------------------------------------
MAPA_TEMPLATE = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>OSIGhost - Mapa</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>html,body{{margin:0;height:100%;background:#0d0d0d;color:#eaeaea;font-family:Consolas,monospace}}
#top{{padding:8px 14px;background:#1a0000;border-bottom:2px solid #c00;font-size:14px}}
#map{{height:calc(100% - 38px)}}</style></head><body>
<div id="top"><b style="color:#e00">OSIGhost</b> · Geolocalización · {total} punto(s) · {fecha}</div>
<div id="map"></div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
var pts = {datos};
var map = L.map('map').setView([20,0], 2);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{maxZoom:18,attribution:'&copy; OpenStreetMap'}}).addTo(map);
var b = [];
pts.forEach(function(p){{
  var c = p.tipo==='ARCHIVO' ? '#ff9800' : '#e00000';
  L.circleMarker([p.lat,p.lon],{{radius:7,color:c,fillColor:c,fillOpacity:.7}}).addTo(map).bindPopup(p.html);
  b.push([p.lat,p.lon]);
}});
if (b.length) map.fitBounds(b,{{padding:[40,40],maxZoom:12}});
</script></body></html>"""

CAMPOS_CSV = ["tipo", "etiqueta", "origen", "pais", "codigo_pais", "region", "ciudad",
              "lat", "lon", "asn", "organizacion", "vpn_proxy", "hosting"]


def mod_exportar():
    _section("EXPORTAR MAPA Y CSV")
    if not SESSION_ROWS:
        _warn("Todavía no hay resultados en esta sesión. Corré alguna consulta primero.")
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    sello = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta_csv = os.path.join(OUT_DIR, f"geolocalizacion_{sello}.csv")
    ruta_map = os.path.join(OUT_DIR, f"geolocalizacion_{sello}.html")

    with open(ruta_csv, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=CAMPOS_CSV, extrasaction="ignore")
        w.writeheader()
        w.writerows(SESSION_ROWS)

    puntos = []
    for r in SESSION_ROWS:
        if r.get("lat") is None or r.get("lon") is None:
            continue
        lineas = [f"<b>{html.escape(str(r['etiqueta']))}</b> ({r['tipo']})"]
        ubic = ", ".join(str(x) for x in (r.get("ciudad"), r.get("region"), r.get("pais")) if x)
        if ubic:
            lineas.append(html.escape(ubic))
        if r.get("organizacion"):
            lineas.append(html.escape(str(r["organizacion"])))
        if r.get("asn"):
            lineas.append(html.escape(str(r["asn"])))
        if r.get("origen"):
            lineas.append("origen: " + html.escape(str(r["origen"])))
        puntos.append({"lat": r["lat"], "lon": r["lon"], "tipo": r["tipo"], "html": "<br>".join(lineas)})

    datos_js = json.dumps(puntos).replace("</", "<\\/")
    with open(ruta_map, "w", encoding="utf-8") as fh:
        fh.write(MAPA_TEMPLATE.format(total=len(puntos), fecha=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                                      datos=datos_js))
    _ok(f"CSV  : {ruta_csv}  ({len(SESSION_ROWS)} fila(s))")
    if puntos:
        _ok(f"Mapa : {ruta_map}  ({len(puntos)} punto(s) con coordenadas)")
        _info("El mapa se abre en el navegador (carga los tiles de OpenStreetMap por internet).")
    else:
        _warn("Ningún resultado tenía coordenadas: se generó el mapa vacío.")


# ---------------------------------------------------------------------------
# Wrappers interactivos (los llama el submenú de osighost.py)
# ---------------------------------------------------------------------------
def tool_ip_dominio():
    raw = _pedir("IP o dominio (ej: 8.8.8.8  ·  ejemplo.com)", "IP/DOMINIO")
    if raw:
        mod_ip_dominio(raw)


def tool_lote():
    ruta = _pedir("Ruta del archivo con IPs o logs (txt, csv, log)", "ARCHIVO")
    if not ruta:
        return
    esperados = _pedir_paises()
    mod_lote_ips(ruta, esperados)


def tool_infra():
    raw = _pedir("Dominio del cliente (ej: ejemplo.com)", "DOMINIO")
    if not raw:
        return
    esperados = _pedir_paises()
    mod_infraestructura(raw, esperados)


def tool_metadatos():
    raw = _pedir("Ruta del archivo (jpg, png, pdf, docx, xlsx, pptx)", "ARCHIVO")
    if raw:
        mod_metadatos(raw)


def tool_metadatos_carpeta():
    raw = _pedir("Ruta de la carpeta a analizar", "CARPETA")
    if raw:
        mod_metadatos_carpeta(raw)


def tool_telefono():
    raw = _pedir("Número (ej: +54 11 5555-1234) o ruta de un archivo con uno por línea", "TELEFONO")
    if not raw:
        return
    region = "AR"
    if not raw.startswith("+"):
        r = _pedir("País por defecto si el número no trae +  (ENTER = AR)", "PAIS")
        if r:
            region = r.upper()
    mod_telefono(raw, region)


def tool_exportar():
    mod_exportar()
