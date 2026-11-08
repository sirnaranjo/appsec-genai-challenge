"""Endpoints del servidor con el análisis del LLM simulado."""

import pytest
from fastapi.testclient import TestClient

from recibos import verificar_firma
from server import ajustes, main, recibos, registro
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


def test_analisis_aprobado_incluye_recibo_verificable(monkeypatch, llave_publica):
    monkeypatch.setattr(main, "analizar", lambda solicitud: [hallazgo("BAJA")])
    datos = cliente.post("/analyze", json={**SOLICITUD, "tree_base": "b" * 40}).json()
    contenido = verificar_firma(datos["recibo"], llave_publica)
    assert contenido["sub"] == "dev"
    assert contenido["tree"] == "a" * 40
    assert contenido["base"] == "b" * 40
    assert contenido["analisis"] == datos["id_analisis"]
    assert contenido["advertencias"] == 1


def test_analisis_rechazado_no_incluye_recibo(monkeypatch):
    monkeypatch.setattr(main, "analizar", lambda solicitud: [hallazgo("ALTA")])
    assert cliente.post("/analyze", json=SOLICITUD).json()["recibo"] is None


def test_commit_sin_codigo_recibe_recibo_sin_llamar_al_llm(monkeypatch):
    def no_llamar(solicitud):
        raise AssertionError("no debía llamar al LLM")

    monkeypatch.setattr(main, "analizar", no_llamar)
    datos = cliente.post("/analyze", json={**SOLICITUD, "archivos": []}).json()
    assert datos["aprobado"] is True
    assert datos["recibo"]


def test_todos_los_analisis_quedan_registrados(monkeypatch):
    monkeypatch.setattr(main, "analizar", lambda solicitud: [hallazgo("ALTA")])
    id_analisis = cliente.post("/analyze", json=SOLICITUD).json()["id_analisis"]
    filas = registro.buscar_por_tree("a" * 40)
    assert [fila["id"] for fila in filas] == [id_analisis]
    assert filas[0]["usuario"] == "dev"
    assert filas[0]["aprobado"] == 0


def test_sin_llave_de_firma_responde_503(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "analizar", lambda solicitud: [])
    monkeypatch.setattr(ajustes, "RUTA_LLAVE_PRIVADA", tmp_path / "no_existe.pem")
    recibos.llave_privada.cache_clear()
    assert cliente.post("/analyze", json=SOLICITUD).status_code == 503


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
