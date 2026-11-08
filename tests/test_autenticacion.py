"""Autenticación y autorización en el servidor, con GitHub simulado."""

import httpx
import pytest
from fastapi.testclient import TestClient

from server import ajustes, autenticacion, main
from server.autenticacion import Usuario

cliente = TestClient(main.app)

SOLICITUD = {"tree_hash": "a" * 40, "archivos": [{"ruta": "app.py", "tipo": "diff", "contenido": "+x = 1"}]}
TOKENS = {"token-dev": Usuario(login="Dev", id=1), "token-otro": Usuario(login="otro", id=2)}


@pytest.fixture(autouse=True)
def github_simulado(monkeypatch):
    consultas = []

    def consultar(token):
        consultas.append(token)
        return TOKENS.get(token)

    monkeypatch.setattr(ajustes, "GITHUB_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setattr(ajustes, "GITHUB_OAUTH_CLIENT_SECRET", "secreto")
    monkeypatch.setattr(ajustes, "USUARIOS_PERMITIDOS", {"dev"})
    monkeypatch.setattr(autenticacion, "consultar_github", consultar)
    monkeypatch.setattr(main, "analizar", lambda solicitud: [])
    autenticacion._cache.clear()
    return consultas


def con_token(token):
    return {"Authorization": f"Bearer {token}"}


def test_sin_token_responde_401():
    respuesta = cliente.post("/analyze", json=SOLICITUD)
    assert respuesta.status_code == 401
    assert respuesta.headers["WWW-Authenticate"] == "Bearer"


def test_token_invalido_responde_401():
    assert cliente.post("/analyze", json=SOLICITUD, headers=con_token("falso")).status_code == 401


def test_usuario_no_autorizado_responde_403():
    assert cliente.post("/analyze", json=SOLICITUD, headers=con_token("token-otro")).status_code == 403


def test_usuario_autorizado_sin_importar_mayusculas():
    respuesta = cliente.post("/analyze", json=SOLICITUD, headers=con_token("token-dev"))
    assert respuesta.status_code == 200
    assert respuesta.json()["usuario"] == "Dev"


def test_auth_me_devuelve_el_usuario():
    assert cliente.get("/auth/me", headers=con_token("token-dev")).json() == {"login": "Dev", "id": 1}


def test_la_validacion_se_guarda_en_cache(github_simulado):
    cliente.get("/auth/me", headers=con_token("token-dev"))
    cliente.get("/auth/me", headers=con_token("token-dev"))
    assert github_simulado == ["token-dev"]


def test_la_cache_no_guarda_el_token_en_claro():
    cliente.get("/auth/me", headers=con_token("token-dev"))
    assert "token-dev" not in autenticacion._cache


def test_falla_de_github_responde_503(monkeypatch):
    def falla(token):
        raise httpx.ConnectError("sin red")

    monkeypatch.setattr(autenticacion, "consultar_github", falla)
    assert cliente.get("/auth/me", headers=con_token("token-dev")).status_code == 503


def test_sin_oauth_configurado_responde_503(monkeypatch):
    monkeypatch.setattr(ajustes, "GITHUB_OAUTH_CLIENT_SECRET", "")
    assert cliente.get("/auth/me", headers=con_token("token-dev")).status_code == 503


def test_auth_config_publica_solo_el_client_id():
    assert cliente.get("/auth/config").json() == {"client_id": "client-id"}
