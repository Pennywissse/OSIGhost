# -*- coding: utf-8 -*-
"""
OSIGhost - Actualizador (tecla X del menú principal)

Busca actualizaciones en el repositorio oficial usando git (así funciona
también con el repo privado, con tus credenciales SSH/HTTPS de siempre),
muestra qué cambió y, SOLO si el usuario confirma, actualiza con
`git pull --ff-only`. Nunca pisa cambios locales ni fuerza nada.
"""

import os
import re
import subprocess
import sys

from osighost import RED, WHITE, RESET, GREEN, YELLOW, CYAN, VERSION, REPO_URL

HERE = os.path.dirname(os.path.realpath(__file__))
BRANCH = "main"
_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")


def _info(m):
    print(f"{CYAN}[*]{RESET} {m}")


def _ok(m):
    print(f"{GREEN}[+]{RESET} {m}")


def _warn(m):
    print(f"{YELLOW}[!]{RESET} {m}")


def _err(m):
    print(f"{RED}[-]{RESET} {m}")


def _git(*args, timeout=60):
    """Ejecuta git dentro de la carpeta de OSIGhost. Devuelve (código, salida)."""
    try:
        p = subprocess.run(["git", *args], cwd=HERE, capture_output=True, text=True,
                           timeout=timeout, env=_ENV)
    except FileNotFoundError:
        return 127, "git no está instalado"
    except subprocess.TimeoutExpired:
        return 124, "tiempo de espera agotado"
    return p.returncode, (p.stdout + p.stderr).strip()


def _version_de(texto):
    m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', texto or "", re.M)
    return m.group(1) if m else None


def _confirmar(pregunta):
    try:
        return input(f"\n{WHITE}{pregunta} (s/n) {RESET}> ").strip().lower() in ("s", "si", "sí", "y", "yes")
    except (KeyboardInterrupt, EOFError):
        return False


def _reiniciar():
    _info("Reiniciando OSIGhost...")
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as exc:
        _warn(f"No se pudo reiniciar automáticamente ({exc}). Cerrá y volvé a abrir OSIGhost.")


def buscar_y_actualizar():
    print(f"\n{RED}━━━ ACTUALIZACIONES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}\n")
    _info(f"Versión instalada : {WHITE}v{VERSION}{RESET}")
    _info(f"Repositorio       : {WHITE}{REPO_URL}{RESET}")

    cod, out = _git("--version")
    if cod != 0:
        _err("Hace falta git para actualizar. Instalalo (Kali: sudo apt install git · Termux: pkg install git).")
        return

    cod, _ = _git("rev-parse", "--is-inside-work-tree")
    if cod != 0:
        _warn("Esta copia de OSIGhost no es un clon de git, así que no se puede actualizar sola.")
        _info(f"Clonala con:  git clone {REPO_URL}.git  y usá esa carpeta (ver README).")
        return

    cod, origen = _git("remote", "get-url", "origin")
    if cod != 0:
        _warn("Este clon no tiene remoto 'origin'. Configuralo con:")
        print(f"      git remote add origin {REPO_URL}.git")
        return
    _info(f"Remoto 'origin'   : {origen}")

    _info("Consultando el repositorio...")
    cod, out = _git("fetch", "origin", BRANCH, timeout=45)
    if cod != 0:
        _err("No se pudo consultar el repositorio.")
        for linea in out.splitlines()[-4:]:
            print(f"      {linea}")
        _info("Revisá tu conexión y tus credenciales de GitHub (clave SSH o token). "
              "El repo es privado: sin credenciales válidas no responde.")
        return

    _, atras = _git("rev-list", "--count", f"HEAD..origin/{BRANCH}")
    _, adelante = _git("rev-list", "--count", f"origin/{BRANCH}..HEAD")
    atras = int(atras) if atras.isdigit() else 0
    adelante = int(adelante) if adelante.isdigit() else 0

    _, src = _git("show", f"origin/{BRANCH}:osighost.py")
    remota = _version_de(src)

    if atras == 0:
        _ok(f"Ya tenés la última versión (v{VERSION}).")
        if adelante:
            _info(f"Tenés {adelante} commit(s) locales todavía sin subir al repositorio.")
        return

    print()
    _warn(f"Hay una actualización disponible: v{VERSION} → v{remota or '?'}  ({atras} cambio(s) nuevo(s))")
    _, log = _git("log", "--no-merges", "--format=   • %s (%ar)", f"HEAD..origin/{BRANCH}", "-n", "10")
    if log:
        print(f"\n{WHITE}Cambios nuevos:{RESET}\n{log}")

    if adelante:
        _warn(f"Tu copia tiene {adelante} commit(s) propios que el repositorio no tiene. "
              "No se actualiza automáticamente para no pisarlos: hacé `git pull` a mano.")
        return

    _, sucio = _git("status", "--porcelain", "--untracked-files=no")
    if sucio:
        _warn("Tenés cambios locales sin commitear en estos archivos:")
        for linea in sucio.splitlines()[:10]:
            print(f"      {linea}")
        _info("Guardalos antes (git commit, o git stash) y volvé a buscar actualizaciones.")
        return

    if not _confirmar(f"¿Actualizar ahora a v{remota or 'nueva'}?"):
        _info("Actualización cancelada. No se modificó nada.")
        return

    _, antes = _git("rev-parse", "HEAD")
    cod, out = _git("pull", "--ff-only", "origin", BRANCH, timeout=90)
    if cod != 0:
        _err("No se pudo actualizar. Tu copia quedó como estaba.")
        for linea in out.splitlines()[-4:]:
            print(f"      {linea}")
        return

    _ok(f"OSIGhost actualizado a v{remota or '?'}.")

    _, cambiados = _git("diff", "--name-only", antes, "HEAD")
    if "requirements.txt" in cambiados.splitlines():
        _warn("Cambiaron las dependencias (requirements.txt).")
        if _confirmar("¿Instalar/actualizar dependencias ahora?"):
            req = os.path.join(HERE, "requirements.txt")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "-r", req], check=True)
                _ok("Dependencias actualizadas.")
            except Exception as exc:
                _err(f"Falló la instalación de dependencias: {exc}. Hacelo a mano: pip install -r requirements.txt")

    if _confirmar("¿Reiniciar OSIGhost para usar la nueva versión?"):
        _reiniciar()
    else:
        _info("Los cambios se aplican la próxima vez que abras OSIGhost.")
