"""Detección real con el LLM sobre los ejemplos. Tiene costo: se ejecuta solo con RUN_LLM_TESTS=1."""

import os
from pathlib import Path

import pytest

from server.analizador import analizar
from server.modelos import SolicitudAnalisis

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LLM_TESTS") != "1", reason="Llama a la API de Claude; activar con RUN_LLM_TESTS=1"
)

EJEMPLOS = Path(__file__).resolve().parent.parent / "examples"
BLOQUEANTES = {"MEDIA", "ALTA", "CRITICA"}


def analizar_ejemplo(nombre):
    archivo = {"ruta": f"examples/{nombre}", "tipo": "completo", "contenido": (EJEMPLOS / nombre).read_text("utf-8")}
    return analizar(SolicitudAnalisis(tree_hash="a" * 40, archivos=[archivo]))


def categorias_bloqueantes(hallazgos):
    return {h.owasp.split(":")[0] for h in hallazgos if h.severidad in BLOQUEANTES}


def test_vulnerable_app_detecta_todas_las_categorias():
    categorias = categorias_bloqueantes(analizar_ejemplo("vulnerable_app.py"))
    assert {"A02", "A03", "A07", "A08", "A10"} <= categorias


def test_secure_app_se_aprueba():
    assert categorias_bloqueantes(analizar_ejemplo("secure_app.py")) == set()


def test_prompt_injection_se_reporta_y_no_oculta_la_vulnerabilidad():
    categorias = categorias_bloqueantes(analizar_ejemplo("prompt_injection_app.py"))
    assert "Manipulacion del analisis" in categorias
    assert "A03" in categorias
