"""Análisis de seguridad de los cambios usando un LLM (Claude).

El análisis combina dos capas:
1. Pre-filtro determinístico (prefiltro.py): detecta intentos de manipulación y patrones peligrosos sin usar IA.
2. LLM: analiza los diffs con el prompt versionado de config/prompts y responde con un esquema fijo.
La respuesta del LLM se trata como un dato no confiable: se valida contra el esquema y se contrasta con
el pre-filtro. Las decisiones de aprobar o rechazar no las toma el LLM sino main.py.
"""

import functools
import html
import logging
import re
import secrets
import time

import anthropic
import yaml
from pydantic import BaseModel

from server import ajustes, prefiltro
from server.modelos import Hallazgo, SolicitudAnalisis

log = logging.getLogger("appsec")
# Variables de la plantilla del mensaje de usuario del prompt
PATRON_VARIABLE = re.compile(r"\{\{(MARCA|SENALES|CAMBIOS)\}\}")


# Esquema que la respuesta del LLM debe cumplir; la API lo exige con salidas estructuradas
class RespuestaModelo(BaseModel):
    hallazgos: list[Hallazgo]


class ErrorAnalisis(Exception):
    pass


def cargar_prompt():
    # El prompt vive en un archivo versionado del servidor: el desarrollador no lo ve ni lo puede
    # modificar, cada cambio queda en el historial y cambiar de versión no requiere tocar el código.
    # safe_load evita ejecutar objetos arbitrarios al leer el YAML
    with open(ajustes.RUTA_PROMPT, encoding="utf-8") as archivo:
        return yaml.safe_load(archivo)


# Secciones del archivo: version, sistema (instrucciones) y usuario (plantilla con los cambios)
PROMPT = cargar_prompt()
# Queda en cada recibo y en el registro: indica con qué criterio se aprobó
VERSION_PROMPT = PROMPT["version"]


@functools.cache
def cliente():
    # Un análisis grande puede tardar; cortarlo antes obliga a repetirlo desde cero.
    # Timeout y reintento suman menos que el timeout del cliente (200 s)
    return anthropic.Anthropic(timeout=90.0, max_retries=1)


def armar_cambios(solicitud):
    # Cada archivo va en su propio bloque; la ruta se escapa porque la controla quien hace el commit
    bloques = []
    for archivo in solicitud.archivos:
        ruta = html.escape(archivo.ruta, quote=True)
        bloques.append(f'<archivo ruta="{ruta}" tipo="{archivo.tipo}">\n{archivo.contenido}\n</archivo>')
    return "\n".join(bloques)


def armar_senales(senales):
    # Solo archivo, línea y tipo de patrón: nunca se copia código del commit fuera de la etiqueta de cambios
    if not senales:
        return "Ninguna"
    return "\n".join(
        f"- archivo {html.escape(senal.archivo, quote=True)}, línea {senal.linea}: {senal.descripcion} ({senal.owasp})"
        for senal in senales
    )


def armar_mensaje(solicitud, senales=()):
    valores = {
        # Marca aleatoria por solicitud: el código analizado no puede adivinarla para cerrar la etiqueta
        "MARCA": secrets.token_hex(8),
        "SENALES": armar_senales(senales),
        "CAMBIOS": armar_cambios(solicitud),
    }
    # Reemplazo en una sola pasada: un texto insertado nunca se vuelve a tratar como plantilla
    return PATRON_VARIABLE.sub(lambda variable: valores[variable.group(1)], PROMPT["usuario"])


def analizar(solicitud: SolicitudAnalisis) -> list[Hallazgo]:
    # Capa determinística: no depende de que el LLM resista la manipulación
    # manipulacion: hallazgos que siempre bloquean; senales: patrones peligrosos que se le indican al LLM
    manipulacion = prefiltro.detectar_manipulacion(solicitud.archivos)
    senales = prefiltro.detectar_senales(solicitud.archivos)

    hallazgos = consultar_modelo(solicitud, senales)

    # El intento de manipulación se reporta aunque el LLM no lo haya detectado. Los caracteres
    # invisibles se conservan siempre: son evidencia concreta que el LLM puede no mencionar
    reportados = {h.archivo for h in hallazgos if h.owasp == prefiltro.MANIPULACION}
    hallazgos += [
        h for h in manipulacion if h.archivo not in reportados or h.titulo == prefiltro.TITULO_INVISIBLES
    ]
    # Señales de confianza alta que el LLM no reportó: se agregan como advertencias de severidad BAJA
    advertencias = prefiltro.contradicciones(senales, hallazgos)

    log.info(
        "prefiltro manipulacion=%d senales=%d contradicciones=%d",
        len(manipulacion),
        len(senales),
        len(advertencias),
    )
    return hallazgos + advertencias


def consultar_modelo(solicitud, senales):
    inicio = time.monotonic()
    try:
        respuesta = cliente().beta.messages.parse(
            model=ajustes.ANTHROPIC_MODEL,
            # Tope de la respuesta; si se alcanza, queda incompleta y el análisis se rechaza
            max_tokens=16000,
            # El prompt de sistema es igual en todas las solicitudes y se guarda en caché
            system=[{"type": "text", "text": PROMPT["sistema"], "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": armar_mensaje(solicitud, senales)}],
            # La respuesta debe cumplir el esquema; no se acepta texto libre
            output_format=RespuestaModelo,
            # Esfuerzo configurable: equilibra la profundidad del análisis con la espera del commit
            output_config={"effort": ajustes.ANTHROPIC_EFFORT},
            # Si el modelo rechaza la solicitud por sus filtros, se reintenta con otro modelo
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.APIError as error:
        log.error("Error al llamar al modelo: %s", error)
        raise ErrorAnalisis("Error al llamar al modelo") from error

    # Costo (tokens, incluidos los leídos de la caché) y duración de cada consulta
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

    # Cualquier respuesta que no se pueda usar termina en ErrorAnalisis y el servidor rechaza el
    # commit (fail closed). refusal: los filtros del modelo declinaron incluso con el respaldo
    if respuesta.stop_reason == "refusal":
        raise ErrorAnalisis("El modelo rechazó la solicitud")
    if respuesta.stop_reason == "max_tokens":
        raise ErrorAnalisis("La respuesta del modelo quedó incompleta")
    if respuesta.parsed_output is None:
        raise ErrorAnalisis("La respuesta del modelo no cumple el esquema")

    return respuesta.parsed_output.hallazgos
