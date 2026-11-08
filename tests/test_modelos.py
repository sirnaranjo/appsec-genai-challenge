"""Validación del contrato de la API."""

import pytest
from pydantic import ValidationError

from server.modelos import MAX_CARACTERES_ARCHIVO, SolicitudAnalisis


def datos_solicitud(**cambios):
    datos = {"tree_hash": "a" * 40, "archivos": [{"ruta": "app.py", "tipo": "diff", "contenido": "+x = 1"}]}
    datos.update(cambios)
    return datos


def test_solicitud_valida():
    SolicitudAnalisis(**datos_solicitud())


def test_acepta_tree_hash_sha256():
    SolicitudAnalisis(**datos_solicitud(tree_hash="b" * 64))


@pytest.mark.parametrize("tree_hash", ["abc", "g" * 40, "a" * 39, "A" * 40])
def test_rechaza_tree_hash_invalido(tree_hash):
    with pytest.raises(ValidationError):
        SolicitudAnalisis(**datos_solicitud(tree_hash=tree_hash))


def test_rechaza_campos_desconocidos():
    with pytest.raises(ValidationError):
        SolicitudAnalisis(**datos_solicitud(aprobado=True))


def test_rechaza_solicitud_sin_archivos():
    with pytest.raises(ValidationError):
        SolicitudAnalisis(**datos_solicitud(archivos=[]))


def test_rechaza_tipo_de_archivo_desconocido():
    with pytest.raises(ValidationError):
        SolicitudAnalisis(**datos_solicitud(archivos=[{"ruta": "app.py", "tipo": "otro", "contenido": ""}]))


def test_rechaza_archivo_demasiado_grande():
    archivo = {"ruta": "app.py", "tipo": "completo", "contenido": "x" * (MAX_CARACTERES_ARCHIVO + 1)}
    with pytest.raises(ValidationError):
        SolicitudAnalisis(**datos_solicitud(archivos=[archivo]))


def test_rechaza_cambio_total_demasiado_grande():
    archivos = [{"ruta": f"a{i}.py", "tipo": "completo", "contenido": "x" * 90_000} for i in range(6)]
    with pytest.raises(ValidationError):
        SolicitudAnalisis(**datos_solicitud(archivos=archivos))
