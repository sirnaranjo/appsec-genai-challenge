"""Cliente HTTP para el servidor de análisis."""

import os

import httpx
from dotenv import load_dotenv

load_dotenv()

URL_SERVIDOR = os.environ.get("APPSEC_SERVER_URL", "http://127.0.0.1:8000")
TIMEOUT_SEGUNDOS = 90


class ErrorServidor(Exception):
    pass


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
            f"El servidor respondió con error {error.response.status_code}: {error.response.text}"
        )
    return respuesta.json()
