#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BUSCADOR "Seguí tu envío" — demostración de inyección SQL (Andreani · académico)
================================================================================
Una sola página con la UI de Andreani. El radio escondido abajo a la izquierda
elige el modo:

  - vuln  -> buscar_vulnerable() / login_vulnerable(): la entrada se concatena
             en la consulta (con  ' OR '1'='1  devuelve TODOS los clientes).
  - seg   -> buscar_seguro() / login_seguro(): validación + consulta
             parametrizada. Además, si se detecta un intento de inyección, se
             marca como ACTIVIDAD SOSPECHOSA y se bloquea al cliente por
             1 minuto (rate limiting).

Controles:
  - Contraseñas con PBKDF2-HMAC-SHA256, sal aleatoria por usuario y pepper.
  - Secretos fuera del código: se leen de variables de entorno o de .env.
  - Roles (admin / cliente) verificados en el servidor; panel en /admin.
  - Intentos sospechosos registrados en seguridad.log.

Correr:  copiar .env.example a .env, completar los valores y luego
         python3 buscador.py   ->  http://localhost:8000
Solo biblioteca estándar. index.html, login.html y fondo.svg deben estar
en esta misma carpeta.
"""

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PUERTO = 8000
CARPETA = os.path.dirname(os.path.abspath(__file__))
ARCHIVO_LOG = os.path.join(CARPETA, "seguridad.log")
SEGUNDOS_BLOQUEO = 60       # timeout de 1 minuto ante actividad sospechosa
SEGUNDOS_SESION = 30 * 60   # las sesiones vencen a los 30 minutos
ITERACIONES = 200000        # vueltas de PBKDF2
SAL_FALSA = b"\x00" * 16    # se usa cuando el usuario no existe, para tardar lo mismo

ENVIOS = [
    ("360000000000001", "Juan Pérez",     "30111222", "Av. Siempreviva 742, Bernal",      "En camino"),
    ("360000000000002", "María Gómez",     "28999888", "Calle Falsa 123, Quilmes",         "Entregado"),
    ("360000000000003", "Lucía Fernández", "35444555", "San Martín 456, Avellaneda",       "En sucursal"),
    ("360000000000004", "Carlos Ruiz",     "27333444", "Mitre 789, Lanús",                 "En preparación"),
    ("360000000000005", "Sofía Torres",    "40222111", "Belgrano 321, Berazategui",        "En camino"),
    ("360000000000006", "Diego Sosa",      "33666777", "Rivadavia 1010, Florencio Varela", "Demorado"),
    ("360000000000007", "Valentina Díaz",  "41888999", "Yrigoyen 202, Wilde",              "Entregado"),
    ("360000000000008", "Martín Álvarez",  "29555666", "Lamadrid 55, Bernal",              "En sucursal"),
]

# usuario, variable de entorno con su contraseña, nombre a mostrar, rol.
# Las contraseñas NO están en el código: se leen del entorno (ver cargar_env).
USUARIOS = [
    ("juan",  "JUAN_PASSWORD",  "Juan Pérez",    "cliente"),
    ("maria", "MARIA_PASSWORD", "María Gómez",   "cliente"),
    ("admin", "ADMIN_PASSWORD", "Administrador", "admin"),
]
VARIABLES = ["ADMIN_PASSWORD", "JUAN_PASSWORD", "MARIA_PASSWORD", "APP_PEPPER"]

PATRON_SEGUIMIENTO = re.compile(r"^\d{1,20}$")           # lista de permitidos
# Patrón que delata un intento de inyección SQL (comillas, =, --, ;, OR, AND, etc.)
SOSPECHOSO = re.compile(r"""['";=]|--|\b(or|and|union|select|drop|insert|update|delete)\b""",
                        re.IGNORECASE)

# Clientes bloqueados: IP -> momento (timestamp) hasta el que sigue el bloqueo.
BLOQUEADOS = {}

# Sesiones activas: token de la cookie -> {"nombre", "rol", "vence"}.
SESIONES = {}

# Recorrido de un envío, en orden: título, fecha, hora, detalle (datos ficticios).
PASOS = [
    ("Pendiente de ingreso", "22-11-2024", "13:13",
     "Recibimos la información de tu envío. Estamos esperando que el remitente lo despache."),
    ("Ingresado", "25-11-2024", "08:14",
     "Tu envío fue recibido. Pronto lo enviaremos a la sucursal encargada de la entrega."),
    ("En camino", "25-11-2024", "08:34",
     "Tu envío se encuentra en camino al domicilio de entrega."),
    ("Entregado", "26-11-2024", "11:05",
     "Tu envío fue entregado en el domicilio."),
]
ICONOS = ["📦", "🏢", "🚚", "🏁"]

# Estado guardado en la base -> en qué paso del recorrido está (1 a 4).
PASO_ACTUAL = {"En preparación": 1, "En sucursal": 2, "En camino": 3, "Demorado": 3, "Entregado": 4}

# Detalle del paso actual cuando el estado no coincide con el título genérico.
DETALLE = {
    "En sucursal": "Tu envío fue recibido en la sucursal. Pronto saldrá hacia el destino.",
    "Demorado": "Tu envío sufrió una demora en el traslado. Lo vamos a entregar lo antes posible.",
}


# ---------- secretos y contraseñas ----------
def cargar_env():
    # Lee un .env simple (CLAVE=valor por línea) sin pisar lo que ya esté en el entorno.
    ruta = os.path.join(CARPETA, ".env")
    if os.path.exists(ruta):
        with open(ruta, encoding="utf-8-sig") as f:
            for linea in f:
                linea = linea.strip()
                if not linea or linea.startswith("#") or "=" not in linea:
                    continue
                clave, valor = linea.split("=", 1)
                os.environ.setdefault(clave.strip(), valor.strip().strip("\"'"))
    faltan = [v for v in VARIABLES if not os.environ.get(v)]
    if faltan:
        sys.exit("ERROR: faltan variables de entorno: " + ", ".join(faltan) + ".\n"
                 "Copiá .env.example a .env y completá los valores (o definilas en el entorno).")


def hash_password(password, sal):
    # PBKDF2-HMAC-SHA256 con sal propia de cada usuario y un pepper que vive fuera de la base.
    secreto = (password + os.environ["APP_PEPPER"]).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secreto, sal, ITERACIONES).hex()


def crear_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE envios (
        numero_seguimiento TEXT, cliente TEXT, dni TEXT, direccion TEXT, estado TEXT)""")
    conn.executemany("INSERT INTO envios VALUES (?,?,?,?,?)", ENVIOS)
    # En la base se guardan la sal y el hash, nunca la contraseña.
    conn.execute("CREATE TABLE usuarios (usuario TEXT, sal TEXT, hash TEXT, nombre TEXT, rol TEXT)")
    for usuario, variable, nombre, rol in USUARIOS:
        sal = secrets.token_bytes(16)
        conn.execute("INSERT INTO usuarios VALUES (?,?,?,?,?)",
                     (usuario, sal.hex(), hash_password(os.environ[variable], sal), nombre, rol))
    return conn


# ---------- consultas ----------
def buscar_vulnerable(conn, entrada):
    # La entrada se concatena en la consulta -> inyección SQL.
    sql = "SELECT * FROM envios WHERE numero_seguimiento = '" + entrada + "'"
    try:
        return conn.execute(sql).fetchall(), sql, None
    except sqlite3.Error as e:
        return [], sql, str(e)


def buscar_seguro(conn, entrada):
    # Consulta parametrizada: el '?' nunca se interpreta como código.
    # Solo se piden número y estado: el DNI y la dirección no salen de la base.
    sql = "SELECT numero_seguimiento, estado FROM envios WHERE numero_seguimiento = ?"
    return conn.execute(sql, (entrada,)).fetchall(), sql


def login_vulnerable(conn, usuario, password):
    # El usuario se concatena en las dos consultas -> con  admin' --  se entra sin contraseña.
    # Devuelve ((nombre, rol) o None, mensaje de error de SQLite o None).
    try:
        fila = conn.execute("SELECT sal FROM usuarios WHERE usuario = '" + usuario + "'").fetchone()
        try:
            sal = bytes.fromhex(str(fila[0])) if fila else SAL_FALSA
        except ValueError:
            sal = SAL_FALSA
        sql = ("SELECT nombre, rol FROM usuarios WHERE usuario = '" + usuario +
               "' AND hash = '" + hash_password(password, sal) + "'")
        return conn.execute(sql).fetchone(), None
    except sqlite3.Error as e:
        return None, str(e)


def login_seguro(conn, usuario, password):
    # Consulta parametrizada: el usuario viaja como dato, no como código.
    fila = conn.execute("SELECT sal, hash, nombre, rol FROM usuarios WHERE usuario = ?",
                        (usuario,)).fetchone()
    sal, guardado = (bytes.fromhex(fila[0]), fila[1]) if fila else (SAL_FALSA, "")
    calculado = hash_password(password, sal)  # se calcula siempre: tarda igual exista o no el usuario
    if fila and hmac.compare_digest(calculado, guardado):
        return fila[2], fila[3]
    return None


# ---------- registro de actividad sospechosa ----------
def registrar(ip, modo, campo, entrada):
    # Una línea por intento: fecha, IP, modo, campo, entrada. Nunca se registran contraseñas.
    # json.dumps deja la entrada en una sola línea (no se pueden falsificar renglones del log).
    linea = "\t".join([time.strftime("%Y-%m-%d %H:%M:%S"), ip, modo, campo,
                       json.dumps(entrada[:200], ensure_ascii=False)])
    with open(ARCHIVO_LOG, "a", encoding="utf-8") as f:
        f.write(linea + "\n")


def leer_registro(maximo=100):
    # Últimos intentos registrados, del más reciente al más viejo.
    if not os.path.exists(ARCHIVO_LOG):
        return []
    with open(ARCHIVO_LOG, encoding="utf-8") as f:
        lineas = f.read().splitlines()
    return [l.split("\t", 4) for l in reversed(lineas[-maximo:]) if l.count("\t") >= 4]


# ---------- fragmentos de resultado ----------
def tabla(filas):
    fh = ""
    for fila in filas:
        fh += "<tr>" + "".join("<td>" + html.escape(str(c)) + "</td>" for c in fila) + "</tr>"
    cab = ("<tr><th>N° seguimiento</th><th>Cliente</th><th>DNI</th>"
           "<th>Dirección</th><th>Estado</th></tr>")
    return "<table>" + cab + fh + "</table>"


def resultado_vulnerable(filas, sql, error):
    if error:
        # Solo para la demo: el modo vulnerable muestra el error tal cual lo da SQLite.
        cuerpo = "<div class='alerta'>⚠ Error de SQLite: " + html.escape(error) + "</div>"
    elif not filas:
        cuerpo = "<div class='okmsg'>No se encontraron envíos con ese número.</div>"
    else:
        aviso = ""
        if len(filas) > 1:
            aviso = ("<div class='alerta'>⚠ Se devolvieron " + str(len(filas)) +
                     " envíos. Un número debería devolver UNO: se filtró la base entera "
                     "con los datos de todos los clientes.</div>")
        cuerpo = aviso + tabla(filas)
    return cuerpo + "<div class='sql'>SQL ejecutada:\n" + html.escape(sql) + "</div>"


def mensaje_sospechoso(donde="la búsqueda"):
    return ("<div class='bloqueo'>⛔ <b>Actividad sospechosa detectada.</b><br>"
            "Se identificó un intento de inyección de código en " + donde + ". "
            "Por seguridad, tu acceso quedó bloqueado por 1 minuto.</div>")


def mensaje_bloqueado(restante):
    return ("<div class='bloqueo'>⛔ <b>Acceso bloqueado por actividad sospechosa.</b><br>"
            "Volvé a intentar en " + str(restante) + " segundos.</div>")


def modal_estado(numero, estado):
    # Ventana modal con el estado y el paso a paso del envío encontrado.
    numero, estado = str(numero), str(estado)
    actual = PASO_ACTUAL.get(estado, 1)

    pasos = ""
    for i, icono in enumerate(ICONOS, 1):
        if i > 1:
            pasos += "<span class='l" + (" hecho" if i <= actual else "") + "'></span>"
        clase = "hecho" if i < actual else ("actual" if i == actual else "")
        pasos += "<span class='p " + clase + "'>" + ("✓" if i < actual else icono) + "</span>"

    # Paso a paso: del más reciente al más viejo.
    linea = ""
    for i in range(actual, 0, -1):
        titulo, fecha, hora, detalle = PASOS[i - 1]
        icono = "✓"
        if i == actual:
            titulo, detalle, icono = estado, DETALLE.get(estado, detalle), ICONOS[i - 1]
        linea += ("<li><span class='ic'>" + icono + "</span><b>" + html.escape(titulo) + "</b>"
                  "<div class='fecha'>" + fecha + "<span>" + hora + " hs.</span></div>"
                  "<p>" + html.escape(detalle) + "</p></li>")

    visitas = "" if estado == "Entregado" else "<div class='visitas'><b>Visitas pendientes:</b> 2</div>"

    return ("<div class='overlay' id='modal-estado' onclick='if(event.target===this)this.remove()'>"
            "<div class='modal'>"
            "<button class='cerrar' type='button' aria-label='Cerrar' "
            "onclick=\"document.getElementById('modal-estado').remove()\">&times;</button>"
            "<h2>" + html.escape(estado) + "</h2>"
            "<p class='nro'>Envío N° " + html.escape(numero) + "</p>"
            "<div class='pasos'>" + pasos + "</div>" + visitas +
            "<div class='paso-titulo'>Paso a paso</div>"
            "<ul class='linea'>" + linea + "</ul>"
            "</div></div>")


def pagina_admin(nombre):
    # Panel del administrador: IPs bloqueadas (con botón para desbloquear) y registro de intentos.
    ahora = time.time()
    bloqueos = ""
    for ip, hasta in BLOQUEADOS.items():
        if hasta > ahora:
            bloqueos += ("<tr><td>" + html.escape(ip) + "</td><td>" + str(int(hasta - ahora) + 1) + " s</td>"
                         "<td><form method='post' action='/admin/desbloquear'>"
                         "<input type='hidden' name='ip' value='" + html.escape(ip) + "'>"
                         "<button type='submit'>Desbloquear</button></form></td></tr>")
    if not bloqueos:
        bloqueos = "<tr><td colspan='3'>No hay IPs bloqueadas.</td></tr>"

    eventos = ""
    for campos in leer_registro():
        eventos += "<tr>" + "".join("<td>" + html.escape(c) + "</td>" for c in campos) + "</tr>"
    if not eventos:
        eventos = "<tr><td colspan='5'>Sin intentos registrados.</td></tr>"

    return ("<!doctype html><html lang='es'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<title>Panel de seguridad — Andreani</title><style>"
            "body{font-family:'Poppins',system-ui,'Segoe UI',Arial,sans-serif;margin:0;background:#f4f4f4;color:#20222e}"
            "header{background:#fff;border-bottom:1px solid #eee;padding:14px 32px;display:flex;gap:20px;align-items:center}"
            "header b{color:#E4002B;font-size:20px;flex:1} header a{color:#2962ff;text-decoration:none;font-size:14px}"
            "main{max-width:1000px;margin:30px auto;padding:0 20px} h1{font-size:24px} h2{font-size:17px;margin-top:30px}"
            "table{width:100%;border-collapse:collapse;font-size:14px;background:#fff}"
            "th,td{border:1px solid #e3e3e3;padding:8px 10px;text-align:left} th{background:#fafafa}"
            "td:last-child{font-family:monospace;word-break:break-all}"
            "button{background:#E4002B;color:#fff;border:0;border-radius:16px;padding:6px 14px;cursor:pointer}"
            "footer{background:#2b2b2b;color:#ddd;text-align:center;padding:9px;font-size:12px;margin-top:40px}"
            "</style></head><body>"
            "<header><b>ANDREANI</b><span>Hola, " + html.escape(nombre) + "</span>"
            "<a href='/?modo=seguro'>← Volver al seguimiento</a><a href='/logout'>Salir</a></header>"
            "<main><h1>Panel de seguridad</h1>"
            "<h2>IPs bloqueadas</h2>"
            "<table><tr><th>IP</th><th>Tiempo restante</th><th>Acción</th></tr>" + bloqueos + "</table>"
            "<h2>Registro de actividad sospechosa (últimos 100)</h2>"
            "<table><tr><th>Fecha</th><th>IP</th><th>Modo</th><th>Campo</th><th>Entrada</th></tr>"
            + eventos + "</table></main>"
            "<footer>PROTOTIPO ACADÉMICO · UADE · datos ficticios · no es el sitio real de Andreani</footer>"
            "</body></html>")


class Handler(BaseHTTPRequestHandler):

    def _servir(self, texto, codigo=200):
        self.send_response(codigo)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(texto.encode("utf-8"))

    def _redirigir(self, destino, cookie=None):
        self.send_response(303)
        self.send_header("Location", destino)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _token(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        return cookie["sesion"].value if "sesion" in cookie else ""

    def _sesion(self):
        # Sesión vigente del pedido, o None. Las vencidas se borran.
        token = self._token()
        sesion = SESIONES.get(token)
        if sesion and sesion["vence"] < time.time():
            del SESIONES[token]
            sesion = None
        return sesion

    def _admin(self):
        # Control de acceso del panel, en el servidor y en cada pedido.
        # Devuelve la sesión si es de un admin; si no, responde y devuelve None.
        sesion = self._sesion()
        if not sesion:
            self._redirigir("/login?modo=seguro")
        elif sesion["rol"] != "admin":
            self._servir("<h1>403</h1><p>No tenés permiso para acceder a esta página.</p>", 403)
        else:
            return sesion
        return None

    def _pagina_login(self, modo, msg=""):
        if msg:
            msg = "<div class='msg'>" + msg + "</div>"
        self._servir(self.login_html
                     .replace("<!--MSG-->", msg)
                     .replace("<!--MODO-->", modo)
                     .replace("<!--CHK_V-->", "checked" if modo != "seguro" else "")
                     .replace("<!--CHK_S-->", "checked" if modo == "seguro" else ""))

    def do_GET(self):
        ruta = urlparse(self.path)

        if ruta.path == "/fondo.svg":
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.end_headers()
            self.wfile.write(self.fondo_svg)
            return
        if ruta.path == "/login":
            modo = parse_qs(ruta.query).get("modo", ["vulnerable"])[0]
            return self._pagina_login("seguro" if modo == "seguro" else "vulnerable")
        if ruta.path == "/logout":
            SESIONES.pop(self._token(), None)
            return self._redirigir("/", "sesion=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
        if ruta.path == "/admin":
            sesion = self._admin()
            if sesion:
                self._servir(pagina_admin(sesion["nombre"]))
            return
        if ruta.path != "/":
            return self._servir("<h1>404</h1>", 404)

        params = parse_qs(ruta.query)
        entrada = params.get("q", [""])[0]
        modo = "seguro" if params.get("modo", [""])[0] == "seguro" else "vulnerable"

        ip = self.client_address[0]
        ahora = time.time()
        resultados = ""
        modal = ""

        if ahora < BLOQUEADOS.get(ip, 0):
            # cliente en timeout: no se procesa ninguna búsqueda
            resultados = mensaje_bloqueado(int(BLOQUEADOS[ip] - ahora) + 1)
        elif entrada:
            sospechoso = bool(SOSPECHOSO.search(entrada))
            if sospechoso:
                registrar(ip, modo, "q", entrada)

            if modo == "seguro":
                if sospechoso:
                    # intento de inyección -> bloqueo por 1 minuto
                    BLOQUEADOS[ip] = ahora + SEGUNDOS_BLOQUEO
                    resultados = mensaje_sospechoso()
                elif not PATRON_SEGUIMIENTO.fullmatch(entrada):
                    resultados = "<div class='okmsg'>El número de seguimiento ingresado no es válido.</div>"
                else:
                    try:
                        filas, sql = buscar_seguro(self.conn, entrada)
                    except sqlite3.Error:
                        # mensaje genérico: no se filtran detalles internos
                        filas, sql = None, ""
                        resultados = "<div class='okmsg'>No pudimos procesar la búsqueda. Intentá de nuevo más tarde.</div>"
                    if filas:
                        # Solo el estado del envío: sin DNI ni dirección.
                        numero, estado = filas[0]
                        modal = modal_estado(numero, estado)
                        resultados = ("<div class='okmsg'>Envío N° " + html.escape(numero) + ": <b>"
                                      + html.escape(estado) + "</b></div>"
                                      "<div class='sql'>Consulta parametrizada:\n" + html.escape(sql) + "</div>")
                    elif filas is not None:
                        resultados = "<div class='okmsg'>No se encontraron envíos con ese número.</div>"
            else:
                filas, sql, error = buscar_vulnerable(self.conn, entrada)
                resultados = resultado_vulnerable(filas, sql, error)
                if len(filas) == 1 and len(filas[0]) >= 5:
                    modal = modal_estado(filas[0][0], filas[0][4])

        sesion = self._sesion()
        if sesion:
            panel = "<a class='hola' href='/admin'>Panel</a>" if sesion["rol"] == "admin" else ""
            nav = ("<span class='hola'>Hola, " + html.escape(sesion["nombre"]) + "</span>" + panel +
                   "<a class='btn-ingresar' href='/logout'>Salir</a>")
        else:
            nav = "<a class='btn-ingresar' href='/login?modo=" + modo + "'>Ingresar</a>"

        pagina = (self.index_html
                  .replace("<!--NAV-->", nav)
                  .replace("<!--MODO-->", modo)
                  .replace("<!--QUERY-->", html.escape(entrada))
                  .replace("<!--RESULTADOS-->", resultados)
                  .replace("<!--MODAL-->", modal)
                  .replace("<!--CHK_V-->", "checked" if modo != "seguro" else "")
                  .replace("<!--CHK_S-->", "checked" if modo == "seguro" else ""))
        self._servir(pagina)

    def do_POST(self):
        ruta = urlparse(self.path).path
        largo = int(self.headers.get("Content-Length", 0))
        datos = parse_qs(self.rfile.read(largo).decode("utf-8"))

        if ruta == "/admin/desbloquear":
            if self._admin():
                BLOQUEADOS.pop(datos.get("ip", [""])[0], None)
                self._redirigir("/admin")
            return
        if ruta != "/login":
            return self._servir("<h1>404</h1>", 404)

        usuario = datos.get("usuario", [""])[0]
        password = datos.get("password", [""])[0]
        modo = "seguro" if datos.get("modo", [""])[0] == "seguro" else "vulnerable"

        ip = self.client_address[0]
        ahora = time.time()
        if ahora < BLOQUEADOS.get(ip, 0):
            return self._pagina_login(modo, mensaje_bloqueado(int(BLOQUEADOS[ip] - ahora) + 1))

        sospechoso = bool(SOSPECHOSO.search(usuario))
        if sospechoso:
            registrar(ip, modo, "usuario", usuario)  # solo el usuario, nunca la contraseña

        if modo == "seguro":
            if sospechoso:
                # intento de inyección -> bloqueo por 1 minuto, igual que en el buscador
                BLOQUEADOS[ip] = ahora + SEGUNDOS_BLOQUEO
                return self._pagina_login(modo, mensaje_sospechoso("el ingreso"))
            try:
                fila = login_seguro(self.conn, usuario, password)
            except sqlite3.Error:
                # mensaje genérico: no se filtran detalles internos
                return self._pagina_login(modo, "No pudimos procesar el ingreso. Intentá de nuevo más tarde.")
        else:
            fila, error = login_vulnerable(self.conn, usuario, password)
            if error:
                # Solo para la demo: el modo vulnerable muestra el error tal cual lo da SQLite.
                return self._pagina_login(modo, "Error de SQLite: " + html.escape(error))

        if not fila:
            return self._pagina_login(modo, "Usuario o contraseña incorrectos.")

        # Login correcto: se crea la sesión (vence a los 30 minutos) y se vuelve a la pantalla principal.
        token = secrets.token_hex(16)
        SESIONES[token] = {"nombre": str(fila[0]), "rol": str(fila[1]), "vence": ahora + SEGUNDOS_SESION}
        self._redirigir("/?modo=" + modo, "sesion=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age="
                        + str(SEGUNDOS_SESION))

    def log_message(self, *a):
        pass


def main():
    cargar_env()
    Handler.conn = crear_db()
    with open(os.path.join(CARPETA, "index.html"), encoding="utf-8") as f:
        Handler.index_html = f.read()
    with open(os.path.join(CARPETA, "login.html"), encoding="utf-8") as f:
        Handler.login_html = f.read()
    with open(os.path.join(CARPETA, "fondo.svg"), "rb") as f:
        Handler.fondo_svg = f.read()
    print("Buscador en  http://localhost:%d" % PUERTO)
    print("Radio abajo a la izquierda: vuln / seg.  Ataque:  ' OR '1'='1")
    print("Login: usuarios juan, maria y admin (claves en .env).  Ataque en usuario:  admin' --")
    print("En modo seguro, el ataque dispara bloqueo de 1 minuto por actividad sospechosa.")
    print("Panel de seguridad (solo admin):  /admin   -   Registro:  seguridad.log")
    print("Ctrl+C para cortar.")
    HTTPServer(("localhost", PUERTO), Handler).serve_forever()


if __name__ == "__main__":
    main()
