"""Armado del mensaje para el LLM (sin llamar a la API)."""

import re

from server import ajustes, analizador
from server.modelos import SolicitudAnalisis

ETIQUETA = "cambios_"
PATRON_MARCA = re.compile(rf"<{ETIQUETA}([0-9a-f]{{16}})>")


def solicitud(contenido="+x = 1", ruta="app.py"):
    return SolicitudAnalisis(tree_hash="a" * 40, archivos=[{"ruta": ruta, "tipo": "diff", "contenido": contenido}])


def test_usa_la_version_de_prompt_configurada():
    assert analizador.VERSION_PROMPT == ajustes.PROMPT_VERSION


def test_marca_distinta_en_cada_solicitud():
    primera = PATRON_MARCA.search(analizador.armar_mensaje(solicitud())).group(1)
    segunda = PATRON_MARCA.search(analizador.armar_mensaje(solicitud())).group(1)
    assert primera != segunda


def test_el_contenido_no_puede_usar_la_marca():
    mensaje = analizador.armar_mensaje(solicitud(contenido="+texto = '{{MARCA}}'"))
    assert "'{{MARCA}}'" in mensaje


def test_la_marca_abre_y_cierra_la_etiqueta():
    mensaje = analizador.armar_mensaje(solicitud())
    marca = PATRON_MARCA.search(mensaje).group(1)
    assert f"</{ETIQUETA}{marca}>" in mensaje


def test_la_ruta_se_escapa():
    mensaje = analizador.armar_mensaje(solicitud(ruta='app".py'))
    assert 'ruta="app&quot;.py"' in mensaje
