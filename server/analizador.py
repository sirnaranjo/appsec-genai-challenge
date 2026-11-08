"""Análisis de seguridad de los cambios usando un LLM (Claude)."""

import functools
import html
import logging
import secrets
import time

import anthropic
import yaml
from pydantic import BaseModel

from server import ajustes
from server.modelos import Hallazgo, SolicitudAnalisis

log = logging.getLogger("appsec")


class RespuestaModelo(BaseModel):
    hallazgos: list[Hallazgo]


class ErrorAnalisis(Exception):
    pass


def cargar_prompt():
    # safe_load evita ejecutar objetos arbitrarios al leer el YAML
    with open(ajustes.RUTA_PROMPT, encoding="utf-8") as archivo:
        return yaml.safe_load(archivo)


PROMPT = cargar_prompt()
VERSION_PROMPT = PROMPT["version"]

@functools.cache
def cliente():
    # Un análisis grande puede tardar; cortarlo antes obliga a repetirlo desde cero.
    # Timeout y reintento suman menos que el timeout del cliente (200 s)
    return anthropic.Anthropic(timeout=90.0, max_retries=1)


def armar_cambios(solicitud):
    bloques = []
    for archivo in solicitud.archivos:
        ruta = html.escape(archivo.ruta, quote=True)
        bloques.append(f'<archivo ruta="{ruta}" tipo="{archivo.tipo}">\n{archivo.contenido}\n</archivo>')
    return "\n".join(bloques)


def armar_mensaje(solicitud):
    # Marca aleatoria por solicitud: el código analizado no puede adivinarla para cerrar la etiqueta
    marca = secrets.token_hex(8)
    mensaje = PROMPT["usuario"].replace("{{MARCA}}", marca)
    # Los cambios se insertan al final para que su contenido no se trate como plantilla
    return mensaje.replace("{{CAMBIOS}}", armar_cambios(solicitud))


def analizar(solicitud: SolicitudAnalisis) -> list[Hallazgo]:
    inicio = time.monotonic()
    try:
        respuesta = cliente().beta.messages.parse(
            model=ajustes.ANTHROPIC_MODEL,
            max_tokens=16000,
            # El prompt de sistema es igual en todas las solicitudes y se guarda en caché
            system=[{"type": "text", "text": PROMPT["sistema"], "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": armar_mensaje(solicitud)}],
            # La respuesta debe cumplir el esquema; no se acepta texto libre
            output_format=RespuestaModelo,
            output_config={"effort": ajustes.ANTHROPIC_EFFORT},
            # Si el modelo rechaza la solicitud por sus filtros, se reintenta con otro modelo
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.APIError as error:
        log.error("Error al llamar al modelo: %s", error)
        raise ErrorAnalisis("Error al llamar al modelo") from error

    log.info(
        "modelo=%s request=%s stop=%s tokens_entrada=%d cache_leido=%d tokens_salida=%d segundos=%.1f",
        respuesta.model,
        respuesta._request_id,
        respuesta.stop_reason,
        respuesta.usage.input_tokens,
        respuesta.usage.cache_read_input_tokens or 0,
        respuesta.usage.output_tokens,
        time.monotonic() - inicio,
    )

    if respuesta.stop_reason == "refusal":
        raise ErrorAnalisis("El modelo rechazó la solicitud")
    if respuesta.stop_reason == "max_tokens":
        raise ErrorAnalisis("La respuesta del modelo quedó incompleta")
    if respuesta.parsed_output is None:
        raise ErrorAnalisis("La respuesta del modelo no cumple el esquema")

    return respuesta.parsed_output.hallazgos
