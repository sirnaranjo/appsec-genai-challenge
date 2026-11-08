"""Obtiene desde git la información de los cambios que van a entrar en el commit."""

import subprocess
from pathlib import Path

LINEAS_CONTEXTO = 10


def git(*args):
    # Se ejecuta git sin shell para evitar inyección de comandos
    resultado = subprocess.run(["git", *args], capture_output=True, check=True)
    return resultado.stdout.decode("utf-8", errors="replace")


def git_opcional(*args):
    try:
        return git(*args).strip() or None
    except subprocess.CalledProcessError:
        return None


def tree_hash():
    # Hash del contenido en staging; es el mismo tree que tendrá el commit
    return git("write-tree").strip()


def diff_staged(ruta):
    return git("diff", "--cached", f"-U{LINEAS_CONTEXTO}", "--", ruta)


def contenido_staged(ruta):
    # Se lee la versión del índice, no la del disco
    return git("show", f":{ruta}")


def cambio_de_archivo(ruta):
    diff = diff_staged(ruta)
    if diff:
        return {"ruta": ruta, "tipo": "diff", "contenido": diff}
    # Sin cambios en staging (por ejemplo con --all-files) se envía el archivo completo
    return {"ruta": ruta, "tipo": "completo", "contenido": contenido_staged(ruta)}


def metadatos():
    return {
        # Tree del padre: los diffs se calculan contra él y el verificador comprueba que coincida
        "tree_base": git_opcional("rev-parse", "--verify", "HEAD^{tree}"),
        # Datos informativos: el autor de git no autentica a nadie
        "rama": git_opcional("symbolic-ref", "--short", "HEAD"),
        "commit_padre": git_opcional("rev-parse", "--verify", "HEAD"),
        "repositorio": git_opcional("remote", "get-url", "origin"),
        "autor_git": git_opcional("config", "user.email"),
    }


def ruta_recibo_pendiente():
    # Archivo dentro de .git donde el recibo espera hasta que el hook commit-msg lo agrega al mensaje
    return Path(git("rev-parse", "--git-path", "appsec-recibo").strip())
