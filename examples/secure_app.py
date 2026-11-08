"""Aplicación de ejemplo con la misma funcionalidad de vulnerable_app.py y las vulnerabilidades corregidas."""

import ipaddress
import json
import os
import sqlite3
import subprocess
from html import escape
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request
from werkzeug.security import generate_password_hash

app = Flask(__name__)

CLIMA_API_KEY = os.environ["CLIMA_API_KEY"]
HOSTS_VISTA_PREVIA = {"docs.python.org", "owasp.org"}


@app.route("/ping")
def ping():
    try:
        ip = ipaddress.ip_address(request.args.get("host", ""))
    except ValueError:
        abort(400)
    if not ip.is_global:
        abort(400)
    resultado = subprocess.run(["ping", "-c", "1", str(ip)], capture_output=True, timeout=5, check=False)
    return {"alcanzable": resultado.returncode == 0}


@app.route("/productos")
def buscar_productos():
    nombre = request.args.get("nombre", "")
    conexion = sqlite3.connect("tienda.db")
    filas = conexion.execute(
        "SELECT id, nombre, precio FROM productos WHERE nombre LIKE ?", (f"%{nombre}%",)
    ).fetchall()
    return {"productos": filas}


@app.route("/saludo")
def saludo():
    nombre = request.args.get("nombre", "")
    return f"<h1>Hola {escape(nombre)}</h1>"


@app.route("/vista-previa")
def vista_previa():
    url = request.args.get("url", "")
    partes = urlparse(url)
    if partes.scheme != "https" or partes.hostname not in HOSTS_VISTA_PREVIA:
        abort(400)
    return requests.get(url, timeout=5, allow_redirects=False).text


@app.route("/registro", methods=["POST"])
def registro():
    usuario = request.form["usuario"]
    password_hash = generate_password_hash(request.form["password"])
    with sqlite3.connect("tienda.db") as conexion:
        conexion.execute("INSERT INTO usuarios (usuario, password) VALUES (?, ?)", (usuario, password_hash))
    return {"registrado": usuario}


@app.route("/preferencias")
def preferencias():
    try:
        datos = json.loads(request.cookies.get("preferencias", "{}"))
    except json.JSONDecodeError:
        abort(400)
    if not isinstance(datos, dict):
        abort(400)
    return {"preferencias": datos}


@app.route("/clima")
def clima():
    ciudad = request.args.get("ciudad", "Bogota")
    respuesta = requests.get(
        "https://api.clima.example/v1/actual",
        params={"ciudad": ciudad},
        headers={"Authorization": f"Bearer {CLIMA_API_KEY}"},
        timeout=5,
    )
    return respuesta.json()
