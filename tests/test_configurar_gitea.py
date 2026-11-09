"""Cómo obtiene y dónde guarda configurar_gitea.py la contraseña del administrador de Gitea."""

import pytest
from keyring.errors import NoKeyringError

import configurar_gitea as gitea


@pytest.fixture
def almacen(tmp_path, monkeypatch):
    # Almacén de credenciales en memoria y archivo de respaldo en una carpeta temporal
    guardadas = {}
    monkeypatch.setattr(gitea, "RAIZ", tmp_path)
    monkeypatch.setattr(gitea, "ARCHIVO_CLAVE", tmp_path / "data" / "gitea-administrador.txt")
    monkeypatch.setattr(gitea.keyring, "get_password", lambda servicio, cuenta: guardadas.get((servicio, cuenta)))
    monkeypatch.setattr(gitea.keyring, "set_password",
                        lambda servicio, cuenta, clave: guardadas.__setitem__((servicio, cuenta), clave))
    return guardadas


def sin_almacen(*args):
    raise NoKeyringError()


def test_la_clave_se_guarda_en_el_almacen_del_sistema(almacen):
    assert gitea.guardar_clave("secreta") == gitea.ALMACEN
    assert gitea.leer_clave() == "secreta"
    assert not gitea.ARCHIVO_CLAVE.exists()


def test_sin_almacen_la_clave_se_guarda_en_un_archivo(almacen, monkeypatch):
    monkeypatch.setattr(gitea.keyring, "set_password", sin_almacen)
    monkeypatch.setattr(gitea.keyring, "get_password", sin_almacen)
    gitea.guardar_clave("secreta")
    assert gitea.ARCHIVO_CLAVE.read_text(encoding="utf-8") == "secreta"
    assert gitea.leer_clave() == "secreta"


def test_la_clave_de_una_version_anterior_pasa_del_archivo_al_almacen(almacen):
    gitea.ARCHIVO_CLAVE.parent.mkdir()
    gitea.ARCHIVO_CLAVE.write_text("anterior", encoding="utf-8")
    assert gitea.leer_clave() == "anterior"
    assert almacen[(gitea.SERVICIO_KEYRING, gitea.GITEA)] == "anterior"
    assert not gitea.ARCHIVO_CLAVE.exists()


def respuestas(monkeypatch, *textos):
    pendientes = list(textos)
    monkeypatch.setattr(gitea, "hay_terminal", lambda: True)
    monkeypatch.setattr(gitea.getpass, "getpass", lambda mensaje="": pendientes.pop(0))
    return pendientes


def test_sin_terminal_se_genera_una_clave_aleatoria(monkeypatch):
    monkeypatch.setattr(gitea, "hay_terminal", lambda: False)
    assert len(gitea.pedir_clave()) >= 32


def test_enter_genera_una_clave_aleatoria(monkeypatch):
    respuestas(monkeypatch, "")
    assert len(gitea.pedir_clave()) >= 32


def test_la_clave_indicada_debe_ser_larga_y_confirmarse(monkeypatch):
    pendientes = respuestas(monkeypatch, "corta", "una-clave-larga", "otra-distinta", "una-clave-larga", "una-clave-larga")
    assert gitea.pedir_clave() == "una-clave-larga"
    assert pendientes == []
