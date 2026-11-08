"""Device Flow del cliente con las respuestas de GitHub simuladas."""

import pytest

import autenticacion

SOLICITUD = {"device_code": "dc", "user_code": "ABCD-1234", "interval": 5, "expires_in": 900}


class Respuesta:
    def __init__(self, datos):
        self.datos = datos

    def json(self):
        return self.datos


@pytest.fixture
def github(monkeypatch):
    respuestas = []
    esperas = []
    monkeypatch.setattr(autenticacion.time, "sleep", esperas.append)
    monkeypatch.setattr(autenticacion.httpx, "post", lambda *args, **kwargs: Respuesta(respuestas.pop(0)))
    return respuestas, esperas


def test_espera_hasta_que_el_usuario_autoriza(github):
    respuestas, esperas = github
    respuestas += [{"error": "authorization_pending"}, {"error": "authorization_pending"}, {"access_token": "tok"}]
    assert autenticacion.esperar_autorizacion("id", SOLICITUD) == "tok"
    assert esperas == [5, 5, 5]


def test_slow_down_aumenta_el_intervalo(github):
    respuestas, esperas = github
    respuestas += [{"error": "slow_down", "interval": 10}, {"access_token": "tok"}]
    autenticacion.esperar_autorizacion("id", SOLICITUD)
    assert esperas == [5, 10]


@pytest.mark.parametrize("error", ["access_denied", "expired_token", "incorrect_client_credentials"])
def test_errores_de_github_detienen_el_login(github, error):
    respuestas, _ = github
    respuestas.append({"error": error})
    with pytest.raises(autenticacion.ErrorLogin):
        autenticacion.esperar_autorizacion("id", SOLICITUD)
