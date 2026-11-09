"""Cliente HTTP para el servidor de análisis."""

import os

import httpx
from dotenv import load_dotenv

load_dotenv()

# Servidor de análisis, desde el .env (con Docker Compose, http://127.0.0.1:8001)
URL_SERVIDOR = os.environ.get("APPSEC_SERVER_URL", "http://127.0.0.1:8000")
# Mayor que lo que el servidor puede esperar al LLM (90 s más un reintento)
TIMEOUT_SEGUNDOS = 200
MENSAJE_LOGIN = "Inicia sesión con: python hooks/login.py"


class ErrorServidor(Exception):
    pass


def detalle_error(respuesta):
    # Mensaje del servidor (campo detail de FastAPI) o, si no es JSON, el texto de la respuesta
    try:
        return respuesta.json().get("detail", respuesta.text)
    except ValueError:
        return respuesta.text


def llamar(metodo, ruta, token=None, **opciones):
    encabezados = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        respuesta = httpx.request(metodo, f"{URL_SERVIDOR}{ruta}", headers=encabezados, **opciones)
        respuesta.raise_for_status()
    except httpx.TimeoutException:
        raise ErrorServidor("El servidor de análisis no respondió a tiempo.")
    except httpx.ConnectError:
        raise ErrorServidor(f"No fue posible conectar con el servidor de análisis ({URL_SERVIDOR}).")
    except httpx.HTTPStatusError as error:
        detalle = detalle_error(error.response)
        # 401: sin sesión válida; se indica cómo iniciarla
        if error.response.status_code == 401:
            raise ErrorServidor(f"{detalle}. {MENSAJE_LOGIN}")
        raise ErrorServidor(f"El servidor respondió con error {error.response.status_code}: {detalle}")
    return respuesta.json()


def configuracion_autenticacion():
    return llamar("GET", "/auth/config", timeout=10)


def usuario_actual(token):
    return llamar("GET", "/auth/me", token=token, timeout=30)


def solicitar_analisis(paquete, token):
    return llamar("POST", "/analyze", token=token, json=paquete, timeout=TIMEOUT_SEGUNDOS)
