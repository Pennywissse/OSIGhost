# OSIGhost

Herramienta personal de **reconocimiento y auditoría de seguridad**, creada por *Pennywise*. Pensada para uso propio durante trabajos de pentesting/hacking ético autorizado sobre aplicaciones, redes, VPNs e infraestructura de clientes.

Compatible con **Linux, Windows y Termux**.

---

## ⚠️ Aviso legal — uso responsable

Esta herramienta está diseñada **exclusivamente** para ser usada sobre sistemas, redes o aplicaciones para los que exista **autorización explícita y por escrito** del titular (contrato o alcance de servicio firmado).

- El uso sin autorización sobre sistemas de terceros puede constituir delito según la legislación vigente. En Argentina, aplica principalmente el **art. 153 bis y concordantes del Código Penal** (acceso indebido a sistemas informáticos), además de la **Ley 25.326 de Protección de Datos Personales** en todo lo referido a información personal que pueda aparecer durante un relevamiento.
- Todo escaneo (puertos, red local, fuerza de directorios, etc.) debe estar cubierto por el alcance (*scope*) acordado con el cliente. Fuera de ese alcance, no se debe ejecutar ninguna herramienta.
- Esta herramienta **no reemplaza el asesoramiento legal** de un equipo de abogados sobre el alcance, los términos del contrato o las obligaciones de confidencialidad de cada trabajo.
- Ninguno de los módulos realiza explotación de vulnerabilidades, fuerza bruta de credenciales, generación de payloads ni ataques activos: todo lo que hace es de **solo lectura** (conexiones TCP normales, peticiones HTTP como las haría un navegador, lectura de certificados, lookups DNS/WHOIS públicos).

---

## Instalación

```bash
pip install -r requirements.txt
```

### La pantalla de inicio chequea tu entorno de verdad

Al correr `python3 osighost.py`, mientras se ve la cara de Pennywise y la barra de carga, el paso **"Verificando dependencias..."** no es cosmético: usa `importlib` para confirmar, en la máquina donde estás parado en ese momento, si están instalados `colorama`, `requests`, `beautifulsoup4`, `lxml`, `dnspython`, `cryptography`, `tldextract` y `psutil`.

Si falta algo, apenas termina el splash te lo muestra y te pregunta:

```
¿Instalar ahora la versión más reciente de todas? (s/n) >
```

Si confirmás, corre `pip install --upgrade <paquete>` por cada uno (siempre la última versión disponible, sin pines). El chequeo corre automáticamente en cada arranque; si instalás algo a mitad de sesión, basta con reiniciar OSIGhost.

### Dependencias

| Paquete | Para qué se usa |
|---|---|
| `colorama` | Colores ANSI en Windows |
| `requests` | Peticiones HTTP (headers, crawler, dirsearch, archivos sensibles, secretos, wayback, subdominios) |
| `beautifulsoup4` + `lxml` | Parseo de HTML en el Crawler |
| `dnspython` | Enumeración de registros DNS |
| `cryptography` | Lectura de certificados TLS/SSL |
| `tldextract` | Separar dominio / sufijo (para WHOIS, subdominios) |
| `psutil` | Auditoría local (interfaces de red, puertos en escucha) |
| `phonenumbers` | Geolocalización: datos del plan de numeración telefónica (offline) |
| `Pillow` | Geolocalización: lectura de EXIF/GPS de imágenes |
| `pypdf` | Geolocalización: metadatos de PDF (opcional, hay fallback) |

---

## Estructura del proyecto

```
osighost.py        → punto de entrada: splash, menú principal, chequeo de dependencias
recon.py           → funciones de reconocimiento orientadas a un dominio/IP (headers, ssl, whois, dns, etc.)
netsec.py          → librería de auditoría (TLS, archivos sensibles, secretos) + herramientas
                      de infraestructura (puertos, red local, auditoría local) + reportes
wordlists/common.txt → wordlist para Fuerza de Directorios
reportes/          → se crea sola al generar el primer reporte (HTML + TXT)
```

---

## Menú principal

```
[1]  ── DIAGNÓSTICO Y REPORTE
[2]  ── GEOLOCALIZACIÓN
[3]  ── OPCION 3   (placeholder)
[4]  ── OPCION 4   (placeholder)
[5]  ── OPCION 5   (placeholder)
[6]  ── OPCION 6   (placeholder)
[7]  ── OPCION 7   (placeholder)
[8]  ── OPCION 8   (placeholder)
[9]  ── OPCION 9   (placeholder)
[10] ── OPCION 10  (placeholder)
[0]  ── SALIR
```

La funcionalidad vive en **[1] Diagnóstico y Reporte** y **[2] Geolocalización**. Las opciones 3 a 10 son numeración de referencia, sin herramienta asignada todavía: están ahí para cuando sumemos algo nuevo.

Si en algún momento un menú (el principal o el de adentro de la opción 1) tiene más de 10 opciones y la terminal es lo bastante ancha, se acomoda solo en hasta 3 columnas, manteniendo la estética roja/blanca de siempre. Con una terminal angosta, cae a una sola columna automáticamente.

---

### [1] Diagnóstico y Reporte — todas las herramientas

Al entrar, se abre un submenú con las 12 herramientas de OSIGhost:

| # | Herramienta | Qué hace |
|---|---|---|
| 1 | **Headers HTTP** | Headers generales, headers de seguridad, cuáles faltan, cookies (Secure/HttpOnly) |
| 2 | **SSL / TLS** | Certificado (sujeto, emisor, autofirmado o no, validez "desde/hasta", algoritmo y tamaño de la clave pública, algoritmo de firma, SAN y si el hostname coincide) + **validación real de la cadena de confianza** (si un navegador confiaría en el cert) + auditoría de hardening: qué versiones de TLS acepta el servidor (marca en rojo si acepta TLS 1.0/1.1, obsoletos) y si acepta cifrados débiles (RC4, DES, 3DES, NULL, EXPORT, MD5) |
| 3 | **WHOIS** | **RDAP primero** (HTTPS, estándar moderno — mucho más confiable que el WHOIS clásico porque muchas redes bloquean el puerto 43) con fallback automático a WHOIS clásico multi-hop (IANA → registro → registrador) si RDAP no responde, y volcado crudo como último recurso si ningún campo se reconoce |
| 4 | **DNS** | Registros A/AAAA/CNAME/NS/MX/TXT/SOA/CAA, DNS inverso (PTR) de las IPs, autenticación de correo completa (**SPF + DKIM + DMARC**, con severidad si la política es laxa), estado de **DNSSEC**, e intento de **transferencia de zona (AXFR)** contra cada NS (hallazgo CRÍTICO si algún servidor la permite) |
| 5 | **Subdominios** | Agregación de crt.sh, HackerTarget, CertSpotter y Wayback + **resolución en paralelo** (vivos vs. solo histórico/CT), detección de **DNS wildcard** (para marcar falsos positivos) y detección de **posible subdomain takeover** (CNAME colgado hacia GitHub Pages, Heroku, S3, Azure, Shopify, etc.) |
| 6 | **Crawler** | robots.txt, sitemap.xml (con conteo de URLs), título, meta descripción, **fingerprint de tecnología** (WordPress, Drupal, React, Angular, jQuery, Bootstrap, Cloudflare, etc.), dominios externos referenciados, **formularios** (método, destino, y aviso si envían contraseña por HTTP o sin token CSRF visible), **emails expuestos**, **comentarios HTML sospechosos** (TODO/FIXME/password/debug) + búsqueda de secretos: analiza el HTML y cada `.js` detectado buscando AWS keys, Google API keys, tokens Slack, JWT, claves privadas y asignaciones tipo `api_key=`/`secret=` (los valores se muestran **enmascarados**, ej: `AKIA…MNOP`) |
| 7 | **Fuerza de Directorios** | Prueba ~960 rutas del wordlist genérico + una lista puntual de archivos de configuración/credenciales (`.env`, `.git/config`, `docker-compose.yml`, `id_rsa`, `.aws/credentials`, backups `.sql`/`.zip`, etc.), marcando como **⚠ CRÍTICO** los más graves |
| 8 | **Wayback Machine** | URLs históricas, JS, endpoints de API, rutas y parámetros "jugosos" |
| 9 | **Escaneo de Puertos** | TCP connect scan (sin privilegios root/admin) contra un host o IP, con banner grabbing y **base de ~185 servicios conocidos** (antes salía `?` para casi cualquier puerto fuera de la lista corta original; ahora solo queda sin nombre si ni la tabla propia ni `/etc/services` lo conocen, y en ese caso dice `desconocido` en vez de `?`). Menú de modos: **[1]** puertos comunes, **[2]** bien conocidos (1-1024), **[3]** **TODOS** los puertos (1-65535), **[4]** personalizado (rango o lista, ej: `22,80,443` o `20-25,8000-8100`). Con `Ctrl+C` corta y muestra lo encontrado hasta ese momento |
| 10 | **Descubrir Red (LAN)** | Barrido sobre un rango CIDR (ej: `192.168.1.0/24`). Reporte detallado por host: nombre DNS, MAC y fabricante (si es del mismo segmento), latencia, SO estimado por TTL, tipo de equipo estimado, puertos de servicios comunes con banner, marcas de *este equipo* y *gateway*. Al final: estadísticas y hallazgos por severidad (CRÍTICO/ALTO/MEDIO/BAJO) con la recomendación de cada uno |
| 11 | **Auditoría de Host (IP/Dominio)** | Audita el host/IP/dominio que vos le pasás (no la máquina donde corre OSIGhost): ping/TTL (SO estimado), DNS inverso, escaneo de los puertos relevantes con banner y riesgo por severidad, chequeo rápido del servidor web (Server, headers de seguridad faltantes) si hay HTTP abierto, y auditoría TLS/cifrados si hay HTTPS abierto. Cierra con un resumen de hallazgos |
| 12 | **Generar Reporte de la Sesión** | Junta la salida de todo lo que corriste en la sesión y la exporta a `reportes/` (ver abajo) |

Las herramientas 1 a 8 piden un objetivo (`https://ejemplo.com`, un dominio o una IP) cada vez que las usás. Las 9, 10 y 11 piden host/IP (o rango CIDR en el caso de la 10) según corresponda. El resto no necesita objetivo.

> La **Auditoría Local** (relevamiento de *esta* máquina: procesos, discos, sesiones, firewall local) sigue existiendo como función (`netsec.mod_localaudit`) pero ya no está colgada de ningún número de menú: por su naturaleza no se puede hacer contra una IP remota sin un agente instalado ahí, así que el número 11 pasó a ser la Auditoría de Host de arriba. Si en algún momento se quiere exponer de nuevo (por ejemplo para auditar la propia estación de trabajo durante un pentest interno), basta con sumarle una entrada nueva al `sub_menu`.

Todo sigue siendo **solo lectura**: peticiones GET como las haría cualquier navegador, conexiones TCP normales, nada de fuerza bruta de login ni explotación.

---

### [2] Geolocalización

Geolocalización de **activos y evidencia del cliente**. Código en `geoloc.py`. Todo queda registrado en el reporte de sesión.

| # | Herramienta | Qué hace |
|---|---|---|
| 1 | **IP / Dominio** | País, región, ciudad aprox., ASN, ISP, DNS inverso; marca VPN/proxy/Tor, hosting/datacenter y red móvil (ip-api.com con respaldo ipwho.is) |
| 2 | **Lote de IPs** | Extrae IPs de un archivo o log, las geolocaliza en lote y resume por país y ASN; compara contra los países esperados del negocio |
| 3 | **Infraestructura de un dominio** | Geolocaliza web (A/AAAA), correo (MX) y DNS (NS) y marca lo alojado fuera de la jurisdicción esperada |
| 4 | **Metadatos de archivo** | EXIF de imágenes (GPS, cámara, software), Office (autor, última modificación, empresa) y PDF, con severidad |
| 5 | **Metadatos de carpeta** | Lo mismo, recursivo, con resumen de archivos que filtran GPS o nombres de personas |
| 6 | **Teléfono** | Solo datos del plan de numeración: país, zona, tipo de línea, operadora original, huso horario |
| 7 | **Exportar mapa y CSV** | Mapa HTML (Leaflet/OpenStreetMap) y CSV de todo lo consultado en la sesión, en `reportes/geolocalizacion/` |

**Límites deliberados:** no ubica personas por DNI ni geolocaliza al titular o dispositivo de una línea telefónica. La geolocalización por IP es aproximada (ciudad/región), no un domicilio, y en VPN/proxy/hosting refleja al servicio, no al usuario.

---

## Reportes

Cada herramienta que corrés desde el submenú queda registrada automáticamente **en el momento en que termina** (ves la salida normal en pantalla, en colores, igual que siempre — por detrás se guarda una copia en texto plano, sin barras de progreso). No hace falta salir del submenú: cuando termines el relevamiento, entrá a **Generar Reporte de la Sesión** (opción 12) y vas a tener en `reportes/`:

```
reportes/osighost_reporte_AAAAMMDD_HHMMSS.html
reportes/osighost_reporte_AAAAMMDD_HHMMSS.txt
```

El HTML mantiene la estética roja/negra de OSIGhost y agrupa cada herramienta ejecutada con su hora y su salida completa — listo para adjuntar o convertir a PDF antes de entregarlo al equipo de IT.

---

## Cómo agregar una herramienta nueva

**Si va adentro de Diagnóstico y Reporte** (lo más probable, hoy todo vive ahí):
1. Escribí la función en `netsec.py` (si es de infraestructura/general) o en `recon.py` (si necesita un dominio/IP como objetivo), siguiendo el mismo estilo de impresión (`_section`, `_ok`, `_info`, `_warn`, `_err` con los colores `RED/WHITE/GREEN/YELLOW/CYAN`).
2. En `osighost.py`, agregá una función `_tool_xxx()` que pida los datos necesarios (con `_pedir` o `_pedir_target`) y llame a tu función nueva.
3. Sumale una entrada al diccionario `sub_menu` dentro de `opcion_diagnostico_reporte()`.

**Si va a ser una opción de primer nivel propia** (con su propio flujo, no una herramienta más del diagnóstico):
1. Escribí tu función como arriba.
2. Reemplazá una de las entradas `OPCION 2`..`OPCION 10` en el diccionario `MENU` por tu label y tu función.

En ambos casos no hace falta tocar nada del splash ni del sistema de reportes: todo lo nuevo queda loggeado automáticamente en cuanto se ejecuta desde cualquiera de los dos menús.

---

## Límites conocidos / qué NO hace OSIGhost

Por diseño, a propósito, OSIGhost **no** incluye:

- Explotación de vulnerabilidades ni generación de payloads.
- Fuerza bruta de credenciales (login, SSH, RDP, etc.) ni cracking de contraseñas o de redes WiFi.
- Prueba de credenciales por defecto en dispositivos (cámaras, routers, IoT).
- Sniffing de tráfico o ataques de red activos (ARP spoofing, MITM, etc.).

Para ese tipo de pruebas (que sí pueden formar parte de un pentest con alcance explícito) hay que usar herramientas especializadas y siempre dentro del marco de autorización acordado con el cliente.
