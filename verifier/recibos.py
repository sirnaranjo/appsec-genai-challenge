"""Verificación de los recibos de integridad: firma del servidor y correspondencia con el commit.

Solo necesita la llave pública: puede ejecutarse donde no hay acceso al servidor de análisis.
"""

import base64
import json
import re
import subprocess

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EMISOR = "appsec-genai"
PATRON_TRAILER = re.compile(r"^AppSec-Receipt:\s*(\S+)\s*$", re.MULTILINE)


class ReciboInvalido(Exception):
    pass


def git(*args):
    resultado = subprocess.run(["git", *args], capture_output=True, check=True)
    return resultado.stdout.decode("utf-8", errors="replace").strip()


def cargar_llave_publica(pem):
    llave = serialization.load_pem_public_key(pem)
    if not isinstance(llave, Ed25519PublicKey):
        raise ValueError("La llave pública no es Ed25519")
    return llave


def decodificar(parte):
    return base64.urlsafe_b64decode(parte + "=" * (-len(parte) % 4))


def verificar_firma(recibo, llave):
    partes = recibo.split(".")
    if len(partes) != 3:
        raise ReciboInvalido("el recibo no tiene un formato válido")
    try:
        encabezado = json.loads(decodificar(partes[0]))
        # Solo se acepta EdDSA: evita ataques que cambian el algoritmo del token (por ejemplo "none")
        if encabezado.get("alg") != "EdDSA":
            raise ReciboInvalido("el recibo usa un algoritmo no permitido")
        llave.verify(decodificar(partes[2]), f"{partes[0]}.{partes[1]}".encode())
        return json.loads(decodificar(partes[1]))
    except InvalidSignature:
        raise ReciboInvalido("la firma del recibo no es válida")
    except ValueError:
        raise ReciboInvalido("el recibo no tiene un formato válido")


def extraer_recibo(mensaje):
    # Si hubiera varios, vale el último: es el que agregó el hook commit-msg
    encontrados = PATRON_TRAILER.findall(mensaje)
    return encontrados[-1] if encontrados else None


def tree_del_padre(sha):
    padres = git("log", "-1", "--format=%P", sha).split()
    # En un merge, los cambios se analizan contra el primer padre (la rama donde se integra)
    return git("rev-parse", f"{padres[0]}^{{tree}}") if padres else None


def verificar_commit(sha, llave, usuario_esperado=None):
    recibo = extraer_recibo(git("log", "-1", "--format=%B", sha))
    if not recibo:
        raise ReciboInvalido("el commit no tiene recibo de análisis")

    datos = verificar_firma(recibo, llave)
    if datos.get("iss") != EMISOR:
        raise ReciboInvalido("el recibo no fue emitido por el servidor de análisis")
    if datos.get("aprobado") is not True:
        raise ReciboInvalido("el análisis no fue aprobado")
    # El contenido del commit debe ser exactamente el analizado
    if datos.get("tree") != git("rev-parse", f"{sha}^{{tree}}"):
        raise ReciboInvalido("el contenido del commit no es el que se analizó")
    # Y los cambios deben haberse calculado contra el padre real (detecta, por ejemplo, un --amend)
    if datos.get("base") != tree_del_padre(sha):
        raise ReciboInvalido("el análisis no se calculó contra el padre de este commit")
    if usuario_esperado and str(datos.get("sub", "")).lower() != usuario_esperado.lower():
        raise ReciboInvalido(f"el recibo pertenece a {datos.get('sub')} y no a {usuario_esperado}")
    return datos
