#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSIGhost - Módulo OSINT (personas / empleados)

Reconocimiento PASIVO orientado a evaluaciones de phishing / ingeniería
social. A propósito NO:
  - scrapea LinkedIn (viola sus Términos de Servicio y requiere sesión
    autenticada: haría falta login o un servicio de terceros, que queda
    fuera del "solo lectura" de OSIGhost),
  - ni verifica si un email existe de verdad (eso requiere SMTP probing
    o un servicio externo, y puede alertar al objetivo).

Lo que sí hace, todo local:
  - arma enlaces de búsqueda (Google dorks) para que el analista pivotee
    manualmente a LinkedIn y otras redes,
  - genera los patrones de email corporativo más probables a partir de
    nombre(s) + dominio, para usarlos como punto de partida.
"""
import unicodedata
from urllib.parse import quote_plus

from osighost import RED, WHITE, RESET, GREEN, YELLOW, CYAN


def _section(title):
    bar = "━" * max(40 - len(title), 4)
    print(f"\n{RED}━━━ {title} {bar}{RESET}\n")


def _ok(msg):
    print(f"{GREEN}[+]{RESET} {msg}")


def _info(msg):
    print(f"{CYAN}[*]{RESET} {msg}")


def _warn(msg):
    print(f"{YELLOW}[!]{RESET} {msg}")


# ---------------------------------------------------------------------------
# 1. Perfiles de empleados (dorks de búsqueda, sin scrapear nada)
# ---------------------------------------------------------------------------
DORKS = [
    ("Perfiles de empleados actuales",   'site:linkedin.com/in "{empresa}"'),
    ("Perfiles con cargo técnico",       'site:linkedin.com/in "{empresa}" ("IT" OR "security" OR "admin" OR "sysadmin" OR "devops")'),
    ("Página de la empresa",             'site:linkedin.com/company "{empresa}"'),
    ("Posts / menciones recientes",      'site:linkedin.com/posts "{empresa}"'),
    ("Menciones en otras redes",         '"{empresa}" (site:twitter.com OR site:facebook.com OR site:instagram.com)'),
    ("Documentos públicos con el nombre", '"{empresa}" (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)'),
]


def tool_linkedin_dorks(empresa):
    _section(f"Perfiles de Empleados (dorks) ─ {empresa}")
    _warn("No se scrapea LinkedIn directamente (viola sus Términos de Servicio y requiere sesión "
          "autenticada). Se generan enlaces de búsqueda para pivotear manualmente, navegador en mano.")

    for titulo, patron in DORKS:
        query = patron.format(empresa=empresa)
        url = "https://www.google.com/search?q=" + quote_plus(query)
        print(f"\n   {WHITE}{titulo}{RESET}")
        print(f"   {CYAN}{url}{RESET}")

    _info("Los nombres completos que vayas encontrando manualmente los podés pasar a "
          "'Generar Patrones de Email Corporativo' (opción 2 de este menú).")


# ---------------------------------------------------------------------------
# 2. Patrones de email corporativo (PROBABLES, no verificados)
# ---------------------------------------------------------------------------
EMAIL_PATTERNS = [
    "{f}.{l}", "{f}{l}", "{f}_{l}", "{fi}{l}", "{fi}.{l}",
    "{f}", "{l}.{f}", "{l}{fi}", "{f}{li}",
]


def _normalizar(texto):
    nfkd = unicodedata.normalize("NFKD", texto.lower())
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def tool_email_patterns(dominio, nombres_raw=""):
    _section(f"Patrones de Email Corporativo ─ {dominio}")
    dominio = (dominio or "").strip().lstrip("@")
    if not dominio:
        return _warn("Hace falta un dominio (ej: empresa.com).")

    nombres = [n.strip() for n in (nombres_raw or "").splitlines() if n.strip()]

    if not nombres:
        _info("Sin nombres cargados: mostrando los patrones más comunes con 'Juan Pérez' de ejemplo.")
        for patron in EMAIL_PATTERNS:
            ejemplo = patron.format(f="juan", l="perez", fi="j", li="p") + f"@{dominio}"
            print(f"   {WHITE}{ejemplo}{RESET}")
    else:
        for nombre_completo in nombres:
            partes = _normalizar(nombre_completo).split()
            if len(partes) < 2:
                _warn(f"'{nombre_completo}' — hace falta nombre Y apellido para generar los patrones.")
                continue
            f, l = partes[0], partes[-1]
            fi, li = f[0], l[0]
            print(f"\n   {WHITE}{nombre_completo}{RESET}")
            for patron in EMAIL_PATTERNS:
                email = patron.format(f=f, l=l, fi=fi, li=li) + f"@{dominio}"
                print(f"      {CYAN}{email}{RESET}")

    _warn("Son patrones PROBABLES, no verificados: no se intenta confirmar si el email existe de "
          "verdad (eso requeriría SMTP probing o un servicio de terceros, fuera del alcance de "
          "solo lectura de OSIGhost, y podría alertar al objetivo).")
