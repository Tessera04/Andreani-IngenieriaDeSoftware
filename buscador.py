#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BUSCADOR "Seguí tu envío" — demostración de inyección SQL (Andreani · académico)
================================================================================
Una sola página con la UI de Andreani. El radio escondido abajo a la izquierda
elige el modo:

  - vuln  -> buscar_vulnerable(): la entrada se concatena en la consulta
             (con  ' OR '1'='1  devuelve TODOS los clientes).
  - seg   -> buscar_seguro(): validación + consulta parametrizada. Además,
             si se detecta un intento de inyección, se marca como ACTIVIDAD
             SOSPECHOSA y se bloquea al cliente por 1 minuto (rate limiting).

Correr:  python3 buscador.py   ->  http://localhost:8000
Solo biblioteca estándar. index.html, login.html y fondo.svg deben estar
en esta misma carpeta.
"""

import html
import os
import re
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PUERTO = 8000
CARPETA = os.path.dirname(os.path.abspath(__file__))
SEGUNDOS_BLOQUEO = 60  # timeout de 1 minuto ante actividad sospechosa

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

PATRON_SEGUIMIENTO = re.compile(r"^\d{1,20}$")           # lista de permitidos
# Patrón que delata un intento de inyección SQL (comillas, =, --, ;, OR, AND, etc.)
SOSPECHOSO = re.compile(r"""['";=]|--|\b(or|and|union|select|drop|insert|update|delete)\b""",
                        re.IGNORECASE)

# Clientes bloqueados: IP -> momento (timestamp) hasta el que sigue el bloqueo.
BLOQUEADOS = {}


def crear_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE envios (
        numero_seguimiento TEXT, cliente TEXT, dni TEXT, direccion TEXT, estado TEXT)""")
    conn.executemany("INSERT INTO envios VALUES (?,?,?,?,?)", ENVIOS)
    return conn


def buscar_vulnerable(conn, entrada):
    # La entrada se concatena en la consulta -> inyección SQL.
    sql = "SELECT * FROM envios WHERE numero_seguimiento = '" + entrada + "'"
    return conn.execute(sql).fetchall(), sql


def buscar_seguro(conn, entrada):
    # Consulta parametrizada: el '?' nunca se interpreta como código.
    sql = "SELECT * FROM envios WHERE numero_seguimiento = ?"
    return conn.execute(sql, (entrada,)).fetchall(), sql


# ---------- fragmentos de resultado ----------
def tabla(filas):
    fh = ""
    for fila in filas:
        fh += "<tr>" + "".join("<td>" + html.escape(str(c)) + "</td>" for c in fila) + "</tr>"
    cab = ("<tr><th>N° seguimiento</th><th>Cliente</th><th>DNI</th>"
           "<th>Dirección</th><th>Estado</th></tr>")
    return "<table>" + cab + fh + "</table>"


def resultado_vulnerable(filas, sql):
    if not filas:
        cuerpo = "<div class='okmsg'>No se encontraron envíos con ese número.</div>"
    else:
        aviso = ""
        if len(filas) > 1:
            aviso = ("<div class='alerta'>⚠ Se devolvieron " + str(len(filas)) +
                     " envíos. Un número debería devolver UNO: se filtró la base entera "
                     "con los datos de todos los clientes.</div>")
        cuerpo = aviso + tabla(filas)
    return cuerpo + "<div class='sql'>SQL ejecutada:\n" + html.escape(sql) + "</div>"


def mensaje_sospechoso():
    return ("<div class='bloqueo'>⛔ <b>Actividad sospechosa detectada.</b><br>"
            "Se identificó un intento de inyección de código en la búsqueda. "
            "Por seguridad, tu acceso quedó bloqueado por 1 minuto.</div>")


def mensaje_bloqueado(restante):
    return ("<div class='bloqueo'>⛔ <b>Acceso bloqueado por actividad sospechosa.</b><br>"
            "Volvé a intentar en " + str(restante) + " segundos.</div>")


class Handler(BaseHTTPRequestHandler):

    def _servir(self, texto, codigo=200):
        self.send_response(codigo)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(texto.encode("utf-8"))

    def do_GET(self):
        ruta = urlparse(self.path)

        if ruta.path == "/fondo.svg":
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.end_headers()
            self.wfile.write(self.fondo_svg)
            return
        if ruta.path == "/login":
            return self._servir(self.login_html.replace("<!--MSG-->", ""))
        if ruta.path != "/":
            return self._servir("<h1>404</h1>", 404)

        params = parse_qs(ruta.query)
        entrada = params.get("q", [""])[0]
        modo = params.get("modo", ["vulnerable"])[0]

        ip = self.client_address[0]
        ahora = time.time()
        resultados = ""

        if ahora < BLOQUEADOS.get(ip, 0):
            # cliente en timeout: no se procesa ninguna búsqueda
            resultados = mensaje_bloqueado(int(BLOQUEADOS[ip] - ahora) + 1)
        elif entrada:
            if modo == "seguro":
                if PATRON_SEGUIMIENTO.fullmatch(entrada):
                    filas, sql = buscar_seguro(self.conn, entrada)
                    if filas:
                        resultados = tabla(filas) + "<div class='sql'>Consulta parametrizada:\n" + html.escape(sql) + "</div>"
                    else:
                        resultados = "<div class='okmsg'>No se encontraron envíos con ese número.</div>"
                elif SOSPECHOSO.search(entrada):
                    # intento de inyección -> bloqueo por 1 minuto
                    BLOQUEADOS[ip] = ahora + SEGUNDOS_BLOQUEO
                    resultados = mensaje_sospechoso()
                else:
                    resultados = "<div class='okmsg'>El número de seguimiento ingresado no es válido.</div>"
            else:
                filas, sql = buscar_vulnerable(self.conn, entrada)
                resultados = resultado_vulnerable(filas, sql)

        pagina = (self.index_html
                  .replace("<!--QUERY-->", html.escape(entrada))
                  .replace("<!--RESULTADOS-->", resultados)
                  .replace("<!--CHK_V-->", "checked" if modo != "seguro" else "")
                  .replace("<!--CHK_S-->", "checked" if modo == "seguro" else ""))
        self._servir(pagina)

    def do_POST(self):
        if urlparse(self.path).path == "/login":
            msg = "<div class='msg'>El ingreso se habilita con los controles de seguridad del prototipo.</div>"
            return self._servir(self.login_html.replace("<!--MSG-->", msg))
        self._servir("<h1>404</h1>", 404)

    def log_message(self, *a):
        pass


def main():
    Handler.conn = crear_db()
    with open(os.path.join(CARPETA, "index.html"), encoding="utf-8") as f:
        Handler.index_html = f.read()
    with open(os.path.join(CARPETA, "login.html"), encoding="utf-8") as f:
        Handler.login_html = f.read()
    with open(os.path.join(CARPETA, "fondo.svg"), "rb") as f:
        Handler.fondo_svg = f.read()
    print("Buscador en  http://localhost:%d" % PUERTO)
    print("Radio abajo a la izquierda: vuln / seg.  Ataque:  ' OR '1'='1")
    print("En modo seguro, el ataque dispara bloqueo de 1 minuto por actividad sospechosa.")
    print("Ctrl+C para cortar.")
    HTTPServer(("localhost", PUERTO), Handler).serve_forever()


if __name__ == "__main__":
    main()
