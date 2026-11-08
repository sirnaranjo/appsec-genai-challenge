"""Cliente HTTP para el servidor de análisis."""

import os

import httpx
from dotenv import load_dotenv

load_dotenv()

URL_SERVIDOR = os.environ.get("APPSEC_SERVER_URL", "http://127.0.0.1:8000")
TIMEOUT_SEGUNDOS = 200


class ErrorServidor(Exception):
    pass


def detalle_error(respuesta):
    try:
        return respuesta.json().get("detail", respuesta.text)
    except ValueError:
        return respuesta.text


def solicitar_analisis(paquete):
    try:
        respuesta = httpx.post(f"{URL_SERVIDOR}/analyze", json=paquete, timeout=TIMEOUT_SEGUNDOS)
        respuesta.raise_for_status()
    except httpx.TimeoutException:
        raise ErrorServidor("El servidor de análisis no respondió a tiempo.")
    except httpx.ConnectError:
        raise ErrorServidor(f"No fue posible conectar con el servidor de análisis ({URL_SERVIDOR}).")
    except httpx.HTTPStatusError as error:
        raise ErrorServidor(
            f"El servidor respondió con error {error.response.status_code}: {detalle_error(error.response)}"
        )
    return respuesta.json()
