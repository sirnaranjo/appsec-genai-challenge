"""Endpoints del servidor con el análisis del LLM simulado."""

import pytest
from fastapi.testclient import TestClient

from server import ajustes, main
from server.analizador import ErrorAnalisis
from server.autenticacion import Usuario, usuario_autenticado
from server.modelos import Hallazgo

cliente = TestClient(main.app)

SOLICITUD = {"tree_hash": "a" * 40, "archivos": [{"ruta": "app.py", "tipo": "diff", "contenido": "+x = 1"}]}


def hallazgo(severidad):
    return Hallazgo(
        owasp="A03:2021-Injection",
        titulo="Prueba",
        archivo="app.py",
        severidad=severidad,
        riesgo="Riesgo",
        solucion="Solución",
    )


@pytest.fixture(autouse=True)
def configuracion(monkeypatch):
    monkeypatch.setattr(ajustes, "SEVERIDAD_BLOQUEO", "MEDIA")
    # La autenticación se prueba aparte en test_autenticacion.py
    main.app.dependency_overrides[usuario_autenticado] = lambda: Usuario(login="dev", id=1)
    yield
    main.app.dependency_overrides.clear()


def test_health():
    assert cliente.get("/health").json() == {"estado": "ok"}


@pytest.mark.parametrize(
    "severidades, aprobado",
    [([], True), (["BAJA"], True), (["MEDIA"], False), (["ALTA"], False), (["BAJA", "CRITICA"], False)],
)
def test_umbral_de_bloqueo(monkeypatch, severidades, aprobado):
    monkeypatch.setattr(main, "analizar", lambda solicitud: [hallazgo(s) for s in severidades])
    respuesta = cliente.post("/analyze", json=SOLICITUD)
    assert respuesta.status_code == 200
    assert respuesta.json()["aprobado"] is aprobado
    assert len(respuesta.json()["hallazgos"]) == len(severidades)


def test_respuesta_incluye_trazabilidad(monkeypatch):
    monkeypatch.setattr(main, "analizar", lambda solicitud: [])
    datos = cliente.post("/analyze", json=SOLICITUD).json()
    assert datos["id_analisis"]
    assert datos["usuario"] == "dev"
    assert datos["version_prompt"] == ajustes.PROMPT_VERSION
    assert datos["severidad_bloqueo"] == "MEDIA"


def test_error_del_modelo_responde_503_sin_detalles_internos(monkeypatch):
    def falla(solicitud):
        raise ErrorAnalisis("detalle interno")

    monkeypatch.setattr(main, "analizar", falla)
    respuesta = cliente.post("/analyze", json=SOLICITUD)
    assert respuesta.status_code == 503
    assert "detalle interno" not in respuesta.text


def test_solicitud_invalida_responde_422():
    respuesta = cliente.post("/analyze", json={**SOLICITUD, "tree_hash": "abc"})
    assert respuesta.status_code == 422
