"""Recibos de integridad: el servidor certifica con su firma qué contenido analizó, para quién y con qué resultado.

El recibo es un JWT firmado con Ed25519 (alg EdDSA) que viaja en el mensaje del commit.
"""

import base64
import functools
import hashlib
import json
import time

from cryptography.hazmat.primitives import serialization

from server import ajustes


class ErrorRecibo(Exception):
    pass


def b64url(datos):
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def json_canonico(datos):
    return json.dumps(datos, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()


@functools.cache
def llave_privada():
    try:
        return serialization.load_pem_private_key(ajustes.RUTA_LLAVE_PRIVADA.read_bytes(), password=None)
    except (OSError, ValueError) as error:
        raise ErrorRecibo(f"No fue posible cargar la llave de firma: {error}") from error


def id_llave():
    # Identifica la llave con la que se firmó; permite rotarla sin invalidar los recibos anteriores
    publica = llave_privada().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(publica).hexdigest()[:16]


def huella_contenido(archivos):
    # Huella de exactamente lo que se envió al LLM: ruta y hash de cada fragmento, en orden fijo
    pares = sorted([archivo.ruta, hashlib.sha256(archivo.contenido.encode()).hexdigest()] for archivo in archivos)
    return hashlib.sha256(json_canonico(pares)).hexdigest()


def firmar(contenido):
    encabezado = b64url(json_canonico({"alg": "EdDSA", "typ": "JWT", "kid": id_llave()}))
    cuerpo = b64url(json_canonico(contenido))
    firma = llave_privada().sign(f"{encabezado}.{cuerpo}".encode())
    return f"{encabezado}.{cuerpo}.{b64url(firma)}"


def emitir(solicitud, usuario, id_analisis, advertencias, modelo, version_prompt):
    return firmar(
        {
            "iss": ajustes.EMISOR_RECIBOS,
            "sub": usuario.login,
            "uid": usuario.id,
            "iat": int(time.time()),
            "analisis": id_analisis,
            "aprobado": True,
            # tree: contenido completo del commit; base: tree del padre contra el que se calcularon los cambios
            "tree": solicitud.tree_hash,
            "base": solicitud.tree_base,
            "contenido": huella_contenido(solicitud.archivos),
            "archivos": len(solicitud.archivos),
            "advertencias": advertencias,
            "modelo": modelo,
            "prompt": version_prompt,
        }
    )
