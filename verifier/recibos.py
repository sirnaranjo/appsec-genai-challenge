"""Verificación de los recibos de integridad: firma del servidor y correspondencia con el commit.

Solo necesita la llave pública: puede ejecutarse donde no hay acceso al servidor de análisis.
"""

import base64
import hashlib
import json
import re
import subprocess

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from identify.identify import tags_from_filename

EMISOR = "appsec-genai"
ID_HOOK = "genai-scan"
PATRON_TRAILER = re.compile(r"^AppSec-Receipt:\s*(\S+)\s*$", re.MULTILINE)
ARBOL_VACIO = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# Deben coincidir con OPCIONES_DIFF en hooks/git_cambios.py: el diff tiene que salir idéntico
OPCIONES_DIFF = [
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--no-relative",
    "--full-index",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--diff-algorithm=myers",
    "--indent-heuristic",
    "-U10",
]


class ReciboInvalido(Exception):
    pass


def git(*args):
    resultado = subprocess.run(["git", *args], capture_output=True, check=True)
    return resultado.stdout.decode("utf-8", errors="replace")


def cargar_llave_publica(pem):
    llave = serialization.load_pem_public_key(pem)
    if not isinstance(llave, Ed25519PublicKey):
        raise ValueError("La llave pública no es Ed25519")
    return llave


def filtros_del_hook(ruta_config):
    # Los mismos tipos de archivo y exclusiones que usa el hook, leídos de una configuración confiable
    configuracion = yaml.safe_load(ruta_config.read_text(encoding="utf-8"))
    for repo in configuracion["repos"]:
        for hook in repo["hooks"]:
            if hook["id"] == ID_HOOK:
                exclude = hook.get("exclude")
                return set(hook.get("types_or", [])), re.compile(exclude) if exclude else None
    raise ValueError(f"No se encontró el hook {ID_HOOK} en {ruta_config}")


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


def padres(sha):
    return git("log", "-1", "--format=%P", sha).split()


def tree(revision):
    return git("rev-parse", f"{revision}^{{tree}}").strip()


def es_merge_sin_cambios_propios(sha):
    # Un merge cuyo contenido es exactamente la combinación automática de sus padres no agrega código:
    # cubre el botón Merge de GitHub, que crea commits sin pasar por los hooks
    lista = padres(sha)
    if len(lista) != 2:
        return False
    combinado = subprocess.run(["git", "merge-tree", "--write-tree", *lista], capture_output=True)
    if combinado.returncode != 0:
        return False
    return combinado.stdout.decode().split()[0] == tree(sha)


def archivos_de_codigo(desde, hasta, filtros):
    tipos, exclusion = filtros
    cambiados = git("diff", "--name-only", "--no-renames", "--diff-filter=d", "-z", desde, hasta).split("\0")
    return {
        ruta
        for ruta in cambiados
        if ruta and tipos & tags_from_filename(ruta) and not (exclusion and exclusion.search(ruta))
    }


def diff_de_archivo(desde, hasta, ruta):
    return git("-c", "core.quotepath=on", "diff", *OPCIONES_DIFF, desde, hasta, "--", ruta)


def huella(pares):
    # Mismo cálculo que server/recibos.py: ruta y hash de cada fragmento, en orden fijo
    canonico = json.dumps(sorted(pares), separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonico.encode()).hexdigest()


def verificar_contenido(sha, datos, filtros):
    lista = padres(sha)
    desde = lista[0] if lista else ARBOL_VACIO
    rutas = datos.get("rutas")
    if not isinstance(rutas, list):
        raise ReciboInvalido("el recibo no indica qué archivos se analizaron")

    # Todo archivo de código que cambió en el commit debe haberse enviado al análisis
    sin_analizar = archivos_de_codigo(desde, sha, filtros) - set(rutas)
    if sin_analizar:
        raise ReciboInvalido(f"hay archivos de código que no se analizaron: {', '.join(sorted(sin_analizar))}")

    # Y lo que vio el LLM debe ser exactamente lo que cambió: detecta un cliente que envía diffs falsos
    pares = [[ruta, hashlib.sha256(diff_de_archivo(desde, sha, ruta).encode()).hexdigest()] for ruta in rutas]
    if huella(pares) != datos.get("contenido"):
        raise ReciboInvalido("lo que se analizó no coincide con los cambios del commit")


def verificar_commit(sha, llave, filtros, usuario_esperado=None):
    recibo = extraer_recibo(git("log", "-1", "--format=%B", sha))
    if not recibo:
        if es_merge_sin_cambios_propios(sha):
            return {"sub": "(merge)"}
        raise ReciboInvalido("el commit no tiene recibo de análisis")

    datos = verificar_firma(recibo, llave)
    if datos.get("iss") != EMISOR:
        raise ReciboInvalido("el recibo no fue emitido por el servidor de análisis")
    if datos.get("aprobado") is not True:
        raise ReciboInvalido("el análisis no fue aprobado")
    # El contenido del commit debe ser exactamente el analizado
    if datos.get("tree") != tree(sha):
        raise ReciboInvalido("el contenido del commit no es el que se analizó")
    # Y los cambios deben haberse calculado contra el padre real (detecta, por ejemplo, un --amend)
    lista = padres(sha)
    if datos.get("base") != (tree(lista[0]) if lista else None):
        raise ReciboInvalido("el análisis no se calculó contra el padre de este commit")
    verificar_contenido(sha, datos, filtros)
    if usuario_esperado and str(datos.get("sub", "")).lower() != usuario_esperado.lower():
        raise ReciboInvalido(f"el recibo pertenece a {datos.get('sub')} y no a {usuario_esperado}")
    return datos
