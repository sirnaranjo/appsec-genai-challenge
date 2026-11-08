"""Firma y verificación de los recibos."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recibos import ReciboInvalido, decodificar, extraer_recibo, verificar_firma
from server import recibos as firma
from server.modelos import Archivo

CONTENIDO = {"iss": "appsec-genai", "sub": "dev", "tree": "a" * 40, "aprobado": True}


def test_un_recibo_firmado_se_verifica(llave_publica):
    assert verificar_firma(firma.firmar(CONTENIDO), llave_publica) == CONTENIDO


def test_el_encabezado_identifica_la_llave():
    encabezado = json.loads(decodificar(firma.firmar(CONTENIDO).split(".")[0]))
    assert encabezado["alg"] == "EdDSA"
    assert encabezado["kid"] == firma.id_llave()


def test_un_recibo_modificado_no_se_verifica(llave_publica):
    encabezado, _, sello = firma.firmar(CONTENIDO).split(".")
    falso = firma.b64url(firma.json_canonico({**CONTENIDO, "sub": "otro"}))
    with pytest.raises(ReciboInvalido, match="firma"):
        verificar_firma(f"{encabezado}.{falso}.{sello}", llave_publica)


def test_un_recibo_de_otra_llave_no_se_verifica():
    otra = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(ReciboInvalido, match="firma"):
        verificar_firma(firma.firmar(CONTENIDO), otra)


def test_se_rechaza_el_algoritmo_none(llave_publica):
    encabezado = firma.b64url(json.dumps({"alg": "none"}).encode())
    cuerpo = firma.b64url(json.dumps(CONTENIDO).encode())
    with pytest.raises(ReciboInvalido, match="algoritmo"):
        verificar_firma(f"{encabezado}.{cuerpo}.", llave_publica)


@pytest.mark.parametrize("recibo", ["", "abc", "a.b", "a.b.c", "!!.##.$$"])
def test_se_rechazan_formatos_invalidos(llave_publica, recibo):
    with pytest.raises(ReciboInvalido):
        verificar_firma(recibo, llave_publica)


def test_la_huella_no_depende_del_orden_pero_si_del_contenido():
    a = Archivo(ruta="a.py", tipo="diff", contenido="+x = 1")
    b = Archivo(ruta="b.py", tipo="diff", contenido="+y = 2")
    otro_b = Archivo(ruta="b.py", tipo="diff", contenido="+y = 3")
    assert firma.huella_contenido([a, b]) == firma.huella_contenido([b, a])
    assert firma.huella_contenido([a, b]) != firma.huella_contenido([a, otro_b])


def test_extraer_recibo_toma_el_ultimo():
    mensaje = "Titulo\n\nAppSec-Receipt: falso\n\nAppSec-Receipt: real\n"
    assert extraer_recibo(mensaje) == "real"
    assert extraer_recibo("Titulo sin recibo") is None
