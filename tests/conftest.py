"""Configuración común: cada prueba usa su propia llave de firma y su propia base de datos."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server import ajustes, recibos


@pytest.fixture(autouse=True)
def llave_publica(tmp_path, monkeypatch):
    llave = Ed25519PrivateKey.generate()
    ruta = tmp_path / "llave_privada.pem"
    ruta.write_bytes(
        llave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    monkeypatch.setattr(ajustes, "RUTA_LLAVE_PRIVADA", ruta)
    monkeypatch.setattr(ajustes, "RUTA_BASE_DATOS", tmp_path / "appsec.db")
    recibos.llave_privada.cache_clear()
    yield llave.public_key()
    recibos.llave_privada.cache_clear()
