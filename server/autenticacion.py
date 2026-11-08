"""Identidad del desarrollador a partir de su token OAuth de GitHub.

El hook envía el token obtenido con el Device Flow (hooks/login.py). Aquí se comprueba:
1. Que el token sea válido y haya sido emitido para esta OAuth App.
2. Que el usuario esté en USUARIOS_PERMITIDOS: autenticarse no basta, también hay que estar autorizado.
Respuestas: 401 sin token o con token inválido, 403 sin autorización, 503 si GitHub no responde.
"""

import hashlib
import logging
import time

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from server import ajustes

log = logging.getLogger("appsec")

DURACION_CACHE_SEGUNDOS = 300

esquema_bearer = HTTPBearer(auto_error=False)
_cache = {}


class Usuario(BaseModel):
    login: str
    id: int


def consultar_github(token):
    # GitHub valida el token y además confirma que fue emitido para esta OAuth App:
    # un token personal o de otra aplicación no sirve aunque sea válido
    respuesta = httpx.post(
        f"https://api.github.com/applications/{ajustes.GITHUB_OAUTH_CLIENT_ID}/token",
        auth=(ajustes.GITHUB_OAUTH_CLIENT_ID, ajustes.GITHUB_OAUTH_CLIENT_SECRET),
        json={"access_token": token},
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        timeout=10,
    )
    # 404 o 422: GitHub no reconoce el token para esta app
    if respuesta.status_code in (404, 422):
        return None
    respuesta.raise_for_status()
    datos = respuesta.json()["user"]
    return Usuario(login=datos["login"], id=datos["id"])


def validar_token(token):
    # La caché evita consultar a GitHub en cada commit; por eso una revocación tarda como máximo
    # DURACION_CACHE_SEGUNDOS en aplicarse. Se guarda el hash del token, nunca el token
    clave = hashlib.sha256(token.encode()).hexdigest()
    guardado = _cache.get(clave)
    if guardado and guardado[1] > time.monotonic():
        return guardado[0]

    usuario = consultar_github(token)
    if usuario:
        _cache[clave] = (usuario, time.monotonic() + DURACION_CACHE_SEGUNDOS)
    return usuario


def no_autenticado(mensaje):
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail=mensaje, headers={"WWW-Authenticate": "Bearer"})


def usuario_autenticado(credenciales: HTTPAuthorizationCredentials | None = Depends(esquema_bearer)) -> Usuario:
    # Dependencia de FastAPI: los endpoints que la declaran solo se ejecutan con un usuario autorizado
    if not ajustes.GITHUB_OAUTH_CLIENT_ID or not ajustes.GITHUB_OAUTH_CLIENT_SECRET:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="La autenticación no está configurada en el servidor")
    if credenciales is None:
        raise no_autenticado("Se requiere iniciar sesión")

    try:
        usuario = validar_token(credenciales.credentials)
    except httpx.HTTPError as error:
        # Si GitHub no responde no se puede saber quién es: se rechaza (fail closed)
        log.error("No fue posible validar el token con GitHub: %s", error)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="No fue posible validar la identidad con GitHub")

    if usuario is None:
        raise no_autenticado("El token no es válido o fue revocado")
    if usuario.login.lower() not in ajustes.USUARIOS_PERMITIDOS:
        log.warning("Usuario no autorizado: %s", usuario.login)
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"El usuario {usuario.login} no está autorizado")
    return usuario
