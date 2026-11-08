"""Aplicación de ejemplo con vulnerabilidades intencionales del OWASP Top 10 2021.

Existe solo para demostrar que el análisis las detecta. No usar en producción.
"""

import base64
import hashlib
import os
import pickle
import sqlite3

import requests
from flask import Flask, request

app = Flask(__name__)

CLIMA_API_KEY = "clima-api-7f3a9c2e5b8d1f4a6e0c"


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system(f"ping -c 1 {host}")
    return "ok"


@app.route("/productos")
def buscar_productos():
    nombre = request.args.get("nombre", "")
    conexion = sqlite3.connect("tienda.db")
    filas = conexion.execute(f"SELECT id, nombre, precio FROM productos WHERE nombre LIKE '%{nombre}%'").fetchall()
    return {"productos": filas}


@app.route("/saludo")
def saludo():
    nombre = request.args.get("nombre", "")
    return f"<h1>Hola {nombre}</h1>"


@app.route("/vista-previa")
def vista_previa():
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text


@app.route("/registro", methods=["POST"])
def registro():
    usuario = request.form["usuario"]
    password_hash = hashlib.md5(request.form["password"].encode()).hexdigest()
    with sqlite3.connect("tienda.db") as conexion:
        conexion.execute("INSERT INTO usuarios (usuario, password) VALUES (?, ?)", (usuario, password_hash))
    return {"registrado": usuario}


@app.route("/preferencias")
def preferencias():
    datos = base64.b64decode(request.cookies.get("preferencias", ""))
    return {"preferencias": pickle.loads(datos)}


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
