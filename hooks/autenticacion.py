"""Autenticación del desarrollador con GitHub (OAuth 2.0 Device Flow)."""

import time

import httpx
import keyring
import keyring.errors

SERVICIO_KEYRING = "appsec-genai-challenge"
CUENTA_KEYRING = "github"

URL_CODIGO = "https://github.com/login/device/code"
URL_TOKEN = "https://github.com/login/oauth/access_token"
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class ErrorLogin(Exception):
    pass


# El token se guarda en el almacén de credenciales del sistema operativo, no en un archivo
def token_guardado():
    return keyring.get_password(SERVICIO_KEYRING, CUENTA_KEYRING)


def guardar_token(token):
    keyring.set_password(SERVICIO_KEYRING, CUENTA_KEYRING, token)


def borrar_token():
    try:
        keyring.delete_password(SERVICIO_KEYRING, CUENTA_KEYRING)
    except keyring.errors.PasswordDeleteError:
        pass


def solicitar_codigo(client_id):
    # Sin scopes: el token solo sirve para identificar al usuario (mínimo privilegio)
    respuesta = httpx.post(
        URL_CODIGO, data={"client_id": client_id, "scope": ""}, headers={"Accept": "application/json"}, timeout=10
    )
    respuesta.raise_for_status()
    datos = respuesta.json()
    if "error" in datos:
        raise ErrorLogin(datos.get("error_description", datos["error"]))
    return datos


def esperar_autorizacion(client_id, solicitud):
    # Se consulta a GitHub cada pocos segundos hasta que el usuario autoriza en el navegador
    intervalo = solicitud["interval"]
    limite = time.monotonic() + solicitud["expires_in"]
    while time.monotonic() < limite:
        time.sleep(intervalo)
        datos = httpx.post(
            URL_TOKEN,
            data={"client_id": client_id, "device_code": solicitud["device_code"], "grant_type": GRANT_TYPE},
            headers={"Accept": "application/json"},
            timeout=10,
        ).json()

        if "access_token" in datos:
            return datos["access_token"]
        error = datos.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            intervalo = datos.get("interval", intervalo + 5)
            continue
        if error == "access_denied":
            raise ErrorLogin("La autorización fue rechazada en GitHub.")
        if error == "expired_token":
            break
        raise ErrorLogin(datos.get("error_description", error))
    raise ErrorLogin("El código expiró antes de ser autorizado. Vuelve a intentarlo.")
