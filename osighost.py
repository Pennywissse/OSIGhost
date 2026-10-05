#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSIGhost - Herramienta creada por Pennywise
Compatible con Linux, Windows y Termux.
"""

import os
import random
import re
import shutil
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Soporte de colores (Windows / Linux / Termux)
# ---------------------------------------------------------------------------
try:
    import colorama
    colorama.just_fix_windows_console()
except Exception:
    if os.name == "nt":
        os.system("")  # activa secuencias ANSI en Windows 10+

RED = "\033[91m"
DIM_RED = "\033[31m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

# Colores auxiliares para los módulos (headers/dns/etc). El rojo sigue
# siendo la identidad de OSIGhost; estos son solo para distinguir estados.
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

# Fuerza UTF-8 en la salida (bloques █ ▓ ▒ ░ y la línea fina ─)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ---------------------------------------------------------------------------
# Carteles
# ---------------------------------------------------------------------------
# Cara de Pennywise (pantalla de carga).
# Cada grilla es una imagen de niveles de rojo (0 = vacío ... 7 = más brillante),
# con 2 píxeles por celda de terminal (semibloques ▀ ▄). Hay 3 tamaños y se
# elige el que entre en la terminal.
ART_GRIDS = [
    [
        "0000000000000000000000000023345666544321000000000000000000000000",
        "0000000000000000000000134543110001001234664100000000000000000000",
        "0000000000000000000135421000000000000000136752000000000000000000",
        "0000000000000000014562000000000000000000000257710000000000000000",
        "0000000000000000352000000000000000000000000001463000000000000000",
        "0000000000000025400200000000000000000000000000003510000000000000",
        "0000000000000460000300000000000122000000000000000152000000000000",
        "0000000000004300000400000000000000000000000000300005400000000000",
        "0000000000174000001500000000000001000000000000510000560000000000",
        "0000000001630000005700000000000000000000000000630000035000000000",
        "0000000016100000005700000000000000000000000000740000003500000000",
        "0000000062000000006700000000000000000000000000760000000450000000",
        "0000000530000000007700000000000000000000000000770000000066000000",
        "0000004500000000017700000000000000000000000000770000000017500000",
        "0000027651000000017710000000000000000000000000770000000215700000",
        "0000074220000000007700000000000000000000000000770000000312740000",
        "0000560000000000007710000000000000000000000001770000000111570000",
        "0001720000000000017720000000000000000000000002771000000000374000",
        "0004710000000010017740000000000000000000000003771000000000257100",
        "0126610000000000017750000000000000000000000005671000000000137400",
        "0057620000000000157670000000000000000000000007574100000000016700",
        "0056100000001000057461000000000000000000000017476100000000004710",
        "0174100000001322147463000000000000000000000015276011200000101740",
        "0272000000001443457477400000000000000000000267276432220000000660",
        "0471000000000200013314763100000000000000015761221000230000100571",
        "0650000000000010057753777731000000000012577743776000000000201372",
        "0740000000000011005777752234530000003543325777771001100000112374",
        "0730000000000012400012100000230000004200000232100441000000344675",
        "1732102342000000474100000000020000003000000000016620000000121376",
        "2700000000000000157254100000050000004100000146147100000000110377",
        "3600000000000000017447620000210000000200001476275100000000000057",
        "3600000000000000037207400000000000000000000174047100001222200057",
        "3710000000000000067047100000000000000000000057007300000000000047",
        "3710000000000000272174000000000000000000000017405600000000000057",
        "3762000000000000660671000010000000000000000004701720000000010067",
        "1730000000000003722730000475100000000265000002750660000000010276",
        "0740000000000006607610001727622211111745300000471372000000000275",
        "0640000000000027127300004503766556677701500000275076000000000474",
        "0551001000000047057100006400000000001100610000057047100000013672",
        "0350001000000046066000005600000000000002600000037227100000025770",
        "0160001000000027037000001761000000000016400000167047000000000740",
        "0062001000000006725630000277310000002375000035541174000000012710",
        "0045011000000000576676200004774000057630001563224760000000026700",
        "0027222000000000012664664200267643674100266315766600000000027400",
        "0007654000000000000174024663102455300125650067100010000110047100",
        "0004767211000000000027300056763000146666100371000000000012275000",
        "0000763434210000000005710003646766743630001720000000134556771000",
        "0000373000000000000001751001746645755600016500000000000025750000",
        "0000077101000000000000562000037745771000047100000000000027700000",
        "0000017411000000000000263100005724640000274000000000000157300000",
        "0000004732000000000000064410000000000000570000000000000275000000",
        "0000000674100000000000055430000000000004720000000000001660000000",
        "0000000177300000000000047452200000000027500000000000004700000000",
        "0000000017620000000000037565200000000167000000000000047100000000",
        "0000000002775210000000017237500000002771000000000000471000000000",
        "0000000000277731001000005126763112467610000000000016710000000000",
        "0000000000015764221000002024657767763000000000000057100000000000",
        "0000000000000577220000000032200122100000000000001650000000000000",
        "0000000000000037500000000020100000000000000001047300000000000000",
        "0000000000000001574100000020000000000000000025761000000000000000",
        "0000000000000000026753100030000000000000003477300000000000000000",
        "0000000000000000000257732130000000000002467730000000000000000000",
        "0000000000000000000001356674321121235577642000000000000000000000",
        "0000000000000000000000000245666666665431000000000000000000000000",
    ],
    [
        "000000000000000000134445554443200000000000000000",
        "000000000000000134332000000012566200000000000000",
        "000000000000024621000000000000004673000000000000",
        "000000000001531000000000000000000025400000000000",
        "000000000044202000000000100000000000251000000000",
        "000000000430003000000000110000000022005300000000",
        "000000016300015000000000000000000033000540000000",
        "000000152000037000000000000000000035000044000000",
        "000000510000037000000000000000000047000004400000",
        "000005200000047100000000000000000057000001750000",
        "000047200000057100000000000000000057100001371000",
        "000274300000057100000000000000000057000003265000",
        "000730000000047200000000000000000057100001137100",
        "003700000010057300000000000000000067100000027600",
        "016600000001057400000000000000000167200000014710",
        "037510001000277600000000000000000377510000001740",
        "046100010210176510000000000000000357600000000470",
        "075100000254475761000000000000001646533310000271",
        "073000000120045267520000000000257525300310010173",
        "171000000011067777654310000234577777301100011165",
        "361000000003302442000420000420003531042100024477",
        "461112310000572100000120000300000111740000003267",
        "540000000000165662000310000310003755600000001047",
        "540000000000064372000100000000002724600001121037",
        "540000000000271650000000000000000651720000001037",
        "572000000000653710000000000000000271550000001037",
        "472000000002727410165100000045000065171000002157",
        "261000000006447100456744333564300027265000000067",
        "162000000017274000620433334610500006537100000275",
        "062000000026271000640000000002500003717200002573",
        "053010000007354000274000000026300026527000000370",
        "035021000003757630027740002663003643374000001550",
        "017331000000246756410476447510365365750000003720",
        "006762000000002731465323442236620741000001105600",
        "002765332000000371015764335663005500000123447300",
        "000661110000000066102667576540036000000022477000",
        "000173100000000027200067477100173000000000472000",
        "000047210000000005420004131000560000000012750000",
        "000006730000000004541000000003710000000105600000",
        "000000771000000003753211100027400000000047000000",
        "000000176210000002747300000175000000000371000000",
        "000000027742111001526742135750000000005710000000",
        "000000001575231000224556666200000000046100000000",
        "000000000057300000022100000000000001650000000000",
        "000000000002652000011000000000000356300000000000",
        "000000000000046641021000000000036750000000000000",
        "000000000000000366554211111346764100000000000000",
        "000000000000000001356665556654100000000000000000",
    ],
    [
        "000000000000024434443343100000000000",
        "000000000024422100000024651000000000",
        "000000001432000000000000035300000000",
        "000000034111000000100000000240000000",
        "000000430032000000100000013015100000",
        "000004300062000000000000015000510000",
        "000043000073000000000000027100051000",
        "000350000073000000000000027100037000",
        "001641000073000000000000027100136400",
        "006300000074000000000000027100013700",
        "027100001175000000000000047100001740",
        "066100100376000000000000057400000370",
        "063001132476200000000000057611000172",
        "261000043365631000000002654413100055",
        "350000011177775320001347777202001156",
        "551121002423300130003200342341002467",
        "530011000564200030003000244600000247",
        "520000000274710110000100564500011117",
        "630000000555400000000000162610000117",
        "650000001646103300000210055540000127",
        "440000005464016753334640027471000047",
        "350100006461044133335142005563000166",
        "150100006450027100000151004553010174",
        "051200003665203651015620344460000261",
        "045300000247553266465135465620000560",
        "017631100004514653434651450000133720",
        "005622000001730477676402600001237600",
        "001720000000461027572016200000037100",
        "000372000000164000000055000001164000",
        "000057100000066310100371000000550000",
        "000006730000065730003720000004500000",
        "000000674220022675566200000055000000",
        "000000047410002312220000001540000000",
        "000000001552101100000000365200000000",
        "000000000036644200101246630000000000",
        "000000000000245655556642000000000000",
    ],
]

# Códigos de color de 256 colores para cada nivel (tonos de rojo)
RED_RAMP = [None, 52, 88, 124, 160, 196, 203, 217]

LETTERS = {
    "O": [" ████ ",
          "██  ██",
          "██  ██",
          "██  ██",
          "██  ██",
          " ████ "],
    "S": [" █████",
          "██    ",
          " ████ ",
          "    ██",
          "    ██",
          "█████ "],
    "I": ["██████",
          "  ██  ",
          "  ██  ",
          "  ██  ",
          "  ██  ",
          "██████"],
    "G": [" █████",
          "██    ",
          "██ ███",
          "██  ██",
          "██  ██",
          " █████"],
    "H": ["██  ██",
          "██  ██",
          "██████",
          "██  ██",
          "██  ██",
          "██  ██"],
    "T": ["██████",
          "  ██  ",
          "  ██  ",
          "  ██  ",
          "  ██  ",
          "  ██  "],
}

TITLE = "OSIGHOST"
SUBTITLE = "Herramienta creada por Pennywise"
VERSION = "1.0"
REPO_URL = "https://github.com/Pennywissse/OSIGhost"
DRIP_ROWS = 5


def build_banner():
    """Arma el cartel OSIGHOST con efecto de 'goteo' fantasma."""
    rows = []
    for r in range(6):
        rows.append(" ".join(LETTERS[ch][r] for ch in TITLE))

    width = len(rows[0])
    rng = random.Random(7)  # semilla fija: el cartel siempre se ve igual

    drips = [[" "] * width for _ in range(DRIP_ROWS)]
    shades = ["▓", "▒", "░", "░", "░"]
    for x in range(width):
        if rows[-1][x] == "█" and rng.random() < 0.75:
            length = rng.randint(1, DRIP_ROWS)
            for d in range(length):
                drips[d][x] = shades[d]

    return rows + ["".join(line) for line in drips]


def term_width():
    return shutil.get_terminal_size((80, 24)).columns


def center_block(lines, width):
    """Centra un bloque completo manteniendo la alineación interna."""
    block_w = max(len(l) for l in lines)
    pad = max((width - block_w) // 2, 0)
    return [" " * pad + l for l in lines]


def clear():
    os.system("cls" if os.name == "nt" else "clear")


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def visible_len(texto):
    """Largo de un texto sin contar los códigos de color."""
    return len(_ANSI.sub("", texto))


def box_min_inner():
    """Ancho interno mínimo para que entren los textos del cartel."""
    return max(len(SUBTITLE), len(REPO_URL)) + 4


def box_inner_width(width=None):
    """Ancho interno de los recuadros (cartel y footer comparten el mismo).
    Se adapta a la terminal: ~75% del ancho, entre el mínimo y 110 columnas."""
    minimo = box_min_inner()
    if width is None:
        return minimo
    objetivo = min(int(width * 0.75), 110) - 2
    return max(minimo, objetivo)


def subtitle_box(width):
    """Cartel de doble línea (╔═╗ ║ ╚═╝) con el autor y la URL del repositorio:
    borde rojo, texto en rojo + negrita. Devuelve las líneas ya centradas.
    Si la terminal es muy angosta, cae a texto simple en rojo/negrita."""
    textos = [SUBTITLE, REPO_URL]
    ancho_txt = max(len(t) for t in textos)
    inner_w = box_inner_width(width)
    box_w = inner_w + 2

    if box_w > width:
        return [f"{BOLD}{RED}{t.center(width)}{RESET}" for t in textos]

    pad = " " * ((width - box_w) // 2)
    top = f"{RED}╔{'═' * inner_w}╗{RESET}"
    bot = f"{RED}╚{'═' * inner_w}╝{RESET}"
    medio = [f"{RED}║{BOLD}{t.center(inner_w)}{RESET}{RED}║{RESET}" for t in textos]
    return [pad + top] + [pad + m for m in medio] + [pad + bot]


def show_banner():
    """Cartel OSIGHOST + subtítulo (pantalla del menú)."""
    width = term_width()
    banner = build_banner()

    if max(len(l) for l in banner) > width:
        # Terminal muy angosta (ej. Termux vertical): versión compacta
        banner = ["O S I G H O S T"]

    for line in center_block(banner, width):
        print(f"{RED}{line}{RESET}")

    print()
    for line in subtitle_box(width):
        print(line)
    print()


# ---------------------------------------------------------------------------
# Chequeo real de dependencias (se corre en la pantalla de inicio)
# ---------------------------------------------------------------------------
REQUIRED_MODULES = [
    ("colorama",    "colorama"),
    ("requests",    "requests"),
    ("bs4",         "beautifulsoup4"),
    ("lxml",        "lxml"),
    ("dns",         "dnspython"),
    ("cryptography", "cryptography"),
    ("tldextract",  "tldextract"),
    ("psutil",      "psutil"),
    ("phonenumbers", "phonenumbers"),
    ("PIL",         "Pillow"),
    ("pypdf",       "pypdf"),
]

# Se llena durante splash() con lo que falte, y main() lo usa después para
# ofrecer la instalación (no se puede instalar en medio del render de la
# barra, hay que hacerlo con la pantalla ya liberada).
_dep_missing = []


def check_dependencies():
    import importlib.util
    missing = []
    for mod_name, pip_name in REQUIRED_MODULES:
        if importlib.util.find_spec(mod_name) is None:
            missing.append((mod_name, pip_name))
    return missing


def install_dependencies(missing):
    for mod_name, pip_name in missing:
        print(f"{CYAN}[*]{RESET} Instalando {WHITE}{pip_name}{RESET} (última versión disponible)...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", pip_name],
                check=True,
            )
            print(f"{GREEN}[+]{RESET} {pip_name} instalado/actualizado correctamente.")
        except subprocess.CalledProcessError as exc:
            print(f"{RED}[-]{RESET} No se pudo instalar {pip_name} : {exc}")
        except FileNotFoundError:
            print(f"{RED}[-]{RESET} No se encontró pip en este entorno. Instalá {pip_name} manualmente.")


def resolver_dependencias_faltantes():
    """Muestra lo que falta y, si el usuario quiere, lo instala. Se usa
    tanto al arrancar como desde la opción de diagnóstico del menú."""
    missing = check_dependencies()
    if not missing:
        print(f"\n{GREEN}[+]{RESET} Todas las dependencias están instaladas.")
        return

    print(f"\n{RED}[!]{RESET} Dependencias faltantes:")
    for _, pip_name in missing:
        print(f"    {YELLOW}-{RESET} {pip_name}")

    try:
        resp = input(f"\n{WHITE}¿Instalar ahora la versión más reciente de todas? (s/n) {RESET}> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        resp = "n"

    if resp in ("s", "si", "sí", "y", "yes"):
        install_dependencies(missing)
    else:
        print(f"{YELLOW}[!]{RESET} Algunas herramientas del menú pueden fallar sin esas dependencias.")


# ---------------------------------------------------------------------------
# Pantalla de inicio: cara de Pennywise + barra de carga
# ---------------------------------------------------------------------------
# Cada paso es (texto, función). El chequeo de dependencias es real; el
# resto son pasos cosméticos para que la barra tenga un ritmo parejo.
def _paso_simulado(duracion):
    def _run():
        time.sleep(duracion)
    return _run


def _paso_chequeo_dependencias():
    global _dep_missing
    t0 = time.time()
    _dep_missing = check_dependencies()
    # deja un mínimo de tiempo visible en la barra aunque el chequeo sea instantáneo
    restante = 0.5 - (time.time() - t0)
    if restante > 0:
        time.sleep(restante)


STARTUP_STEPS = [
    ("Iniciando módulos...",        _paso_simulado(0.5)),
    ("Preparando entorno...",       _paso_simulado(0.5)),
    ("Verificando dependencias...", _paso_chequeo_dependencias),
    ("Analizando sistema...",       _paso_simulado(0.6)),
    ("Listo.",                      _paso_simulado(0.3)),
]


def render_progress(width, bar_w, pct, text):
    """Dibuja la barra en la última línea (se actualiza en el lugar)."""
    filled = int(bar_w * pct / 100)
    bar = f"{RED}{'█' * filled}{DIM_RED}{'░' * (bar_w - filled)}{RESET}"
    label = f"[{bar}] {WHITE}{pct:3d}%{RESET}"
    visible_len = bar_w + 2 + 5  # corchetes + " 100%"
    pad = " " * max((width - visible_len) // 2, 0)
    status = text.center(width)
    # sube una línea para refrescar texto + barra juntos
    sys.stdout.write(f"\r\033[2K{WHITE}{status}{RESET}\n\033[2K{pad}{label}\033[1A")
    sys.stdout.flush()


def render_art(grid):
    """Convierte una grilla de niveles en líneas ANSI (2 píxeles por celda)."""
    lines = []
    for y in range(0, len(grid), 2):
        top = grid[y]
        bot = grid[y + 1] if y + 1 < len(grid) else "0" * len(top)
        out = []
        for t, b in zip(top, bot):
            t, b = int(t), int(b)
            if t == 0 and b == 0:
                out.append(" ")
            elif b == 0:
                out.append(f"\033[38;5;{RED_RAMP[t]}m▀\033[0m")
            elif t == 0:
                out.append(f"\033[38;5;{RED_RAMP[b]}m▄\033[0m")
            elif t == b:
                out.append(f"\033[38;5;{RED_RAMP[t]}m█\033[0m")
            else:
                out.append(f"\033[38;5;{RED_RAMP[t]};48;5;{RED_RAMP[b]}m▀\033[0m")
        lines.append("".join(out))
    return lines


def pick_art(cols, rows):
    """Elige la cara más grande que entre en la terminal (None si no entra)."""
    avail = rows - 6  # espacio para margen, estado y barra
    for grid in ART_GRIDS:
        if len(grid[0]) <= cols and len(grid) // 2 <= avail:
            return grid
    smallest = ART_GRIDS[-1]
    if len(smallest[0]) <= cols:
        return smallest
    return None


def splash():
    size = shutil.get_terminal_size((80, 24))
    width = size.columns
    clear()
    print()
    grid = pick_art(width, size.lines)
    if grid:
        pad = " " * max((width - len(grid[0])) // 2, 0)
        for line in render_art(grid):
            print(pad + line)
    else:
        print(f"{RED}{'O S I G H O S T'.center(width)}{RESET}")
    print("\n")

    bar_w = min(40, max(width - 12, 10))
    total = len(STARTUP_STEPS)
    pct = 0
    sys.stdout.write(HIDE_CURSOR)
    try:
        render_progress(width, bar_w, 0, STARTUP_STEPS[0][0])
        for i, (text, func) in enumerate(STARTUP_STEPS):
            target = int((i + 1) * 100 / total)
            steps = max(target - pct, 1)
            t0 = time.time()
            func()
            elapsed = max(time.time() - t0, 0.05)
            delay = min(elapsed / steps, 0.03)
            for p in range(pct + 1, target + 1):
                render_progress(width, bar_w, p, text)
                time.sleep(delay)
            pct = target
        time.sleep(0.4)
    finally:
        sys.stdout.write(f"\033[1B\n{SHOW_CURSOR}")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Opciones del menú
# ---------------------------------------------------------------------------
def pausar():
    input(f"\n{WHITE}Presiona ENTER para volver al menú...{RESET}")


def _pedir(texto, prompt_tag):
    print(f"\n{WHITE}{texto}{RESET}")
    try:
        return input(f"{RED}{prompt_tag}{WHITE} > {RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        return None


def _limpiar_host(raw):
    """Saca protocolo/puerto/ruta de algo tipo URL para dejar solo el host."""
    return raw.split("://")[-1].split("/")[0].split(":")[0]


def _pedir_target():
    """Pide una URL/host/IP y devuelve el Target de recon.py (o None)."""
    import recon

    raw = _pedir("Objetivo (ej: https://ejemplo.com)", "URL")
    if not raw:
        return None
    tgt, error = recon.build_target(raw)
    if error:
        print(f"\n{RED}[-]{RESET} {error}")
        return None
    return tgt


# ---------------------------------------------------------------------------
# Herramientas individuales. Todas viven adentro de la opción 1 (abajo);
# cada una pide lo que necesita y listo, sin menús ni nombres intermedios.
# ---------------------------------------------------------------------------
def _tool_headers():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_headers(tgt)


def _tool_ssl():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_sslinfo(tgt)


def _tool_whois():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_whois(tgt)


def _tool_dns():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_dns(tgt)


def _tool_subdomains():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_subdomains(tgt)


def _tool_crawler():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_crawler(tgt)


def _tool_dirsearch():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_dirsearch(tgt)


def _tool_wayback():
    import recon
    tgt = _pedir_target()
    if tgt:
        recon.mod_wayback(tgt)


def _tool_portscan():
    import netsec
    raw = _pedir("Objetivo (host o IP)", "HOST")
    if not raw:
        return
    host = _limpiar_host(raw)

    # (clave, etiqueta, especificación que recibe netsec.mod_portscan)
    modos = [
        ("1", f"Puertos comunes ({len(netsec.COMMON_PORTS)} puertos)", ""),
        ("2", "Puertos bien conocidos (1-1024)",                   "1-1024"),
        ("3", "TODOS los puertos (1-65535)",                      "todos"),
        ("4", "Personalizado (rango o lista)",                    None),
    ]
    print(f"\n{WHITE}¿Qué puertos querés revisar?{RESET}\n")
    for clave, etiqueta, _ in modos:
        print(f"    {RED}[{clave}]{WHITE} ── {etiqueta}{RESET}")

    eleccion = _pedir("ENTER = comunes", "MODO")
    if eleccion is None:
        return
    eleccion = eleccion.strip()

    if eleccion in ("", "1"):
        spec = ""
    elif eleccion == "2":
        spec = "1-1024"
    elif eleccion == "3" or eleccion.lower() in netsec.ALL_PORTS_KEYWORDS:
        spec = "todos"
    elif eleccion == "4":
        spec = _pedir("Rango o lista (ej: 1-1024  ·  22,80,443  ·  20-25,80,8000-8100)", "PUERTOS")
        if spec is None:
            return
    else:
        # Si escribió directamente un rango/lista (ej: 22,80) lo usamos tal cual
        spec = eleccion

    netsec.mod_portscan(host, spec)


def _tool_netdiscover():
    import netsec
    cidr = _pedir("Rango de red (ej: 192.168.1.0/24)", "RED")
    if not cidr:
        return
    netsec.mod_netdiscover(cidr)


def _tool_hostaudit():
    import netsec
    raw = _pedir("Objetivo a auditar (host, dominio o IP)", "HOST")
    if not raw:
        return
    host = _limpiar_host(raw)
    netsec.mod_hostaudit(host)


def _tool_reporte():
    import netsec
    netsec.mod_report()


# ---------------------------------------------------------------------------
# OPCION 1: Diagnóstico y Reporte — todas las herramientas de OSIGhost.
# ---------------------------------------------------------------------------
def opcion_diagnostico_reporte():
    """OPCION 1: Diagnóstico y Reporte. Acá adentro están TODAS las
    herramientas (reconocimiento web + infraestructura + reporte).

    Cada herramienta se registra EN EL MOMENTO en que se ejecuta
    (netsec.run_and_log), así 'Generar Reporte de la Sesión' ya tiene
    contenido sin necesidad de salir de este submenú."""
    import netsec

    sub_menu = {
        "1":  ("Headers HTTP",                 _tool_headers),
        "2":  ("SSL / TLS",                     _tool_ssl),
        "3":  ("WHOIS",                         _tool_whois),
        "4":  ("DNS",                           _tool_dns),
        "5":  ("Subdominios",                   _tool_subdomains),
        "6":  ("Crawler",                       _tool_crawler),
        "7":  ("Fuerza de Directorios",         _tool_dirsearch),
        "8":  ("Wayback Machine",               _tool_wayback),
        "9":  ("Escaneo de Puertos",            _tool_portscan),
        "10": ("Descubrir Red (LAN)",           _tool_netdiscover),
        "11": ("Auditoría de Host (IP/Dominio)", _tool_hostaudit),
        "12": ("Generar Reporte de la Sesión",  _tool_reporte),
    }
    # El generador de reportes no se registra a sí mismo dentro del reporte.
    SIN_REGISTRO = {"12"}

    while True:
        clear()
        show_banner()
        render_opciones(sub_menu, salir_label="VOLVER")

        try:
            choice = pedir_opcion("DIAGNÓSTICO")
        except (KeyboardInterrupt, EOFError):
            choice = "0"

        if choice == "0":
            return
        if choice in sub_menu:
            label, func = sub_menu[choice]
            try:
                if choice in SIN_REGISTRO:
                    func()
                else:
                    netsec.run_and_log(label, func)
            except KeyboardInterrupt:
                print(f"\n{RED}[-]{RESET} Interrumpido.")
            except Exception as exc:
                print(f"\n{RED}[-]{RESET} Excepción : {exc}")
            pausar()
        else:
            print(f"\n{RED}Opción inválida.{RESET}")
            pausar()


# La opción 1 registra cada herramienta por su cuenta (ver arriba), por eso
# main() no la envuelve en run_and_log: si no, el reporte incluiría los menús
# y quedaría duplicado.
opcion_diagnostico_reporte.registra_por_su_cuenta = True


# ---------------------------------------------------------------------------
# OPCION 2: Geolocalización (IP, dominio, lote de logs, metadatos, teléfono)
# ---------------------------------------------------------------------------
def opcion_geolocalizacion():
    """OPCION 2: Geolocalización de activos y evidencia del cliente. Cada
    herramienta se registra en el reporte de sesión al ejecutarse."""
    import netsec
    import geoloc

    sub_menu = {
        "1": ("IP / Dominio",                         geoloc.tool_ip_dominio),
        "2": ("Lote de IPs (archivo / logs)",         geoloc.tool_lote),
        "3": ("Infraestructura de un dominio",        geoloc.tool_infra),
        "4": ("Metadatos de archivo / imagen (EXIF)", geoloc.tool_metadatos),
        "5": ("Metadatos de una carpeta",             geoloc.tool_metadatos_carpeta),
        "6": ("Teléfono (plan de numeración)",        geoloc.tool_telefono),
        "7": ("Exportar mapa y CSV",                  geoloc.tool_exportar),
    }

    while True:
        clear()
        show_banner()
        render_opciones(sub_menu, salir_label="VOLVER")

        try:
            choice = pedir_opcion("GEOLOCALIZACIÓN")
        except (KeyboardInterrupt, EOFError):
            choice = "0"

        if choice == "0":
            return
        if choice in sub_menu:
            label, func = sub_menu[choice]
            try:
                netsec.run_and_log("Geolocalización · " + label, func)
            except KeyboardInterrupt:
                print(f"\n{RED}[-]{RESET} Interrumpido.")
            except Exception as exc:
                print(f"\n{RED}[-]{RESET} Excepción : {exc}")
            pausar()
        else:
            print(f"\n{RED}Opción inválida.{RESET}")
            pausar()


opcion_geolocalizacion.registra_por_su_cuenta = True


def opcion_placeholder(n):
    def _run():
        print(f"\n{WHITE}Opción {n} todavía no implementada.{RESET}")
        pausar()
    return _run


# Para agregar una herramienta nueva de primer nivel: reemplazá la entrada
# de uno de los placeholders (OPCION 2..10) por tu label y tu función.
# Para agregar una herramienta DENTRO de Diagnóstico y Reporte: sumale una
# entrada al sub_menu de opcion_diagnostico_reporte().
MENU = {
    "1": ("DIAGNÓSTICO Y REPORTE", opcion_diagnostico_reporte),
    "2": ("GEOLOCALIZACIÓN",       opcion_geolocalizacion),
}
for _n in range(3, 11):
    MENU[str(_n)] = (f"OPCION {_n}", opcion_placeholder(_n))


# ---------------------------------------------------------------------------
# Menú
# ---------------------------------------------------------------------------
MAX_COLS = 3
COLUMN_THRESHOLD = 10  # a partir de cuántas opciones se arma en columnas


_PAD_MENU = 0  # margen izquierdo del último menú dibujado (lo usa el prompt)
MENU_SHIFT = 3  # columnas que se corre el menú a la izquierda del centro exacto


def render_opciones(items_dict, salir_label="SALIR", salir_key="0"):
    """Lista [1]..[N] + [0] <salir_label>, centrada como bloque en la
    terminal (la alineación interna se mantiene). Si hay más de
    COLUMN_THRESHOLD opciones, las reparte en hasta MAX_COLS columnas.
    La usan el menú principal y los submenús."""
    global _PAD_MENU
    items = list(items_dict.items()) + [(salir_key, (salir_label, None))]
    num_w = max(len(f"[{k}]") for k, _ in items) + 1

    def celda_texto(key, label):
        return f"[{key}]".ljust(num_w) + " ── " + label

    def celda_color(key, label):
        return f"{RED}{f'[{key}]'.ljust(num_w)}{WHITE} ── {label}{RESET}"

    width = term_width()
    lineas = []  # (texto_coloreado, largo_visible)

    if len(items) <= COLUMN_THRESHOLD:
        for key, (label, _) in items:
            lineas.append((celda_color(key, label), len(celda_texto(key, label))))
    else:
        ancho_celda = max(len(celda_texto(k, v[0])) for k, v in items)
        cols = max(1, min(MAX_COLS, width // (ancho_celda + 3)))
        # las columnas se separan para ocupar el mismo ancho que los recuadros
        objetivo = min(box_inner_width(width) + 2, width - 2)
        extra = (objetivo - cols * ancho_celda) // (cols - 1) if cols > 1 else 3
        separador = " " * max(3, extra)
        filas = -(-len(items) // cols)  # ceil division, orden por columnas
        for r in range(filas):
            partes, largo = [], 0
            for c in range(cols):
                idx = c * filas + r
                if idx >= len(items):
                    continue
                key, (label, _) = items[idx]
                texto = celda_texto(key, label)
                pad = " " * (ancho_celda - len(texto))
                partes.append(celda_color(key, label) + pad)
            linea = separador.join(partes).rstrip()
            lineas.append((linea, visible_len(linea)))

    bloque = max(l for _, l in lineas)
    if len(items) <= COLUMN_THRESHOLD and box_inner_width(width) + 2 <= width:
        # una sola columna: alineada dentro del ancho de los recuadros
        caja_izq = (width - (box_inner_width(width) + 2)) // 2
        _PAD_MENU = caja_izq + max((box_inner_width(width) + 2 - bloque) // 4, 2)
    else:
        _PAD_MENU = max((width - bloque) // 2, 0)
    _PAD_MENU = max(_PAD_MENU - MENU_SHIFT, 0)
    sangria = " " * _PAD_MENU
    for texto, _ in lineas:
        print(sangria + texto)
    print()


def pedir_opcion(etiqueta, footer=False):
    """Lee la opción del menú alineada con el bloque de opciones. Con
    footer=True, el recuadro del pie queda DEBAJO de la línea de tipeo:
    se reserva la línea, se dibuja el pie y el cursor vuelve a subir."""
    sangria = " " * _PAD_MENU
    prompt = f"{sangria}{RED}{etiqueta}{WHITE} > {RESET}"
    if not footer:
        return input(prompt).strip()

    pie = footer_box(term_width())
    print()                       # línea reservada para el tipeo
    for linea in pie:
        print(linea)
    sys.stdout.write(f"\033[{len(pie) + 1}A\r")   # volver a la línea de tipeo
    sys.stdout.flush()
    try:
        return input(prompt).strip()
    finally:
        sys.stdout.write(f"\033[{len(pie)}B\r")  # bajar pasando el pie
        sys.stdout.flush()


def footer_box(width):
    """Recuadro de pie (mismo estilo y ancho que el cartel de arriba):
    versión a la izquierda y tecla de actualización a la derecha."""
    izq_txt, der_txt = f"OSIGhost v{VERSION}", "[X] Buscar actualizaciones"
    inner_w = box_inner_width(width)
    box_w = inner_w + 2

    if box_w > width or len(izq_txt) + len(der_txt) + 4 > inner_w:
        l1, l2 = izq_txt, "[X] Buscar actualizaciones"
        return [" " * max((width - len(l1)) // 2, 0) + f"{WHITE}{l1}{RESET}",
                " " * max((width - len(l2)) // 2, 0) + f"{RED}[X]{WHITE} Buscar actualizaciones{RESET}"]

    hueco = " " * (inner_w - 2 - len(izq_txt) - len(der_txt))
    contenido = (f" {WHITE}{izq_txt}{RESET}{hueco}"
                 f"{RED}[X]{WHITE} Buscar actualizaciones{RESET} ")
    pad = " " * ((width - box_w) // 2)
    return [
        pad + f"{RED}╔{'═' * inner_w}╗{RESET}",
        pad + f"{RED}║{RESET}{contenido}{RED}║{RESET}",
        pad + f"{RED}╚{'═' * inner_w}╝{RESET}",
    ]


def show_menu():
    render_opciones(MENU, salir_label="SALIR")


def main():
    try:
        splash()
    except KeyboardInterrupt:
        sys.stdout.write(SHOW_CURSOR)
        return

    if _dep_missing:
        resolver_dependencias_faltantes()
        pausar()

    import netsec

    while True:
        clear()
        show_banner()
        show_menu()
        try:
            choice = pedir_opcion("OSIGhost", footer=True)
        except (KeyboardInterrupt, EOFError):
            choice = "0"

        if choice == "0":
            print(f"\n{WHITE}Hasta luego.{RESET}")
            break
        if choice.lower() == "x":
            import updater
            try:
                updater.buscar_y_actualizar()
            except KeyboardInterrupt:
                print(f"\n{RED}[-]{RESET} Interrumpido.")
            except Exception as exc:
                print(f"\n{RED}[-]{RESET} Error al buscar actualizaciones : {exc}")
            pausar()
            continue
        if choice in MENU:
            label, func = MENU[choice]
            try:
                if getattr(func, "registra_por_su_cuenta", False):
                    func()
                else:
                    netsec.run_and_log(label, func)
            except KeyboardInterrupt:
                pass
        else:
            print(f"\n{RED}Opción inválida.{RESET}")
            pausar()


if __name__ == "__main__":
    main()
