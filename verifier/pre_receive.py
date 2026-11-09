"""Hook pre-receive para un servidor Git propio: rechaza el push si algún commit nuevo no tiene un recibo válido.

A diferencia de la verificación en GitHub Actions, que corre después del push, este hook se ejecuta
mientras el servidor recibe el push: si falla, ninguna rama se actualiza y el código no queda en el remoto.
Sirve en GitHub Enterprise Server, GitLab autoadministrado, Gitea o un repositorio Git propio.

Git entrega por la entrada estándar una línea por cada rama que se intenta actualizar:
    <hash anterior> <hash nuevo> <rama>

Uso dentro del archivo hooks/pre-receive del repositorio en el servidor:
    python verifier/pre_receive.py --llave /ruta/receipt_public.pem [--usuario-desde VARIABLE]
"""

import argparse
import os
import re
import sys
from pathlib import Path

from recibos import ReciboInvalido, cargar_llave_publica, filtros_desde_texto, git, verificar_commit

SIN_COMMIT = re.compile(r"^0+$")


def commits_que_entran(anterior, nuevo):
    # Todos los commits que se incorporan a la rama, aunque ya existan en otra referencia del servidor:
    # por ejemplo los de un pull request desde un fork, que llegan sin pasar por este hook
    if SIN_COMMIT.match(anterior):
        return git("rev-list", "--reverse", nuevo, "--not", "--branches").split()
    return git("rev-list", "--reverse", f"{anterior}..{nuevo}").split()


def commits_nunca_vistos(nuevo):
    # Los que el servidor recibe por primera vez. Solo a estos se les exige que el recibo sea de quien hace
    # el push: los demás ya llegaron por otra vía, como la rama de un PR que otra persona integra
    return set(git("rev-list", nuevo, "--not", "--all").split())


def filtros_confiables():
    # Se usa la configuración que ya está aceptada en el servidor, no la del push:
    # un push no puede agregar sus propias exclusiones para que un archivo no se exija
    return filtros_desde_texto(git("show", "HEAD:.pre-commit-config.yaml"))


def main():
    parser = argparse.ArgumentParser(description="Hook pre-receive de verificación de recibos de integridad")
    parser.add_argument("--llave", required=True, help="llave pública de los recibos")
    parser.add_argument("--usuario-desde", help="variable de entorno con el usuario autenticado que hace el push")
    argumentos = parser.parse_args()

    llave = cargar_llave_publica(Path(argumentos.llave).read_bytes())
    filtros = filtros_confiables()
    # Cada servidor expone de forma distinta quién hace el push (por ejemplo GITEA_PUSHER_NAME o GL_USERNAME)
    usuario = os.environ.get(argumentos.usuario_desde) if argumentos.usuario_desde else None

    fallidos = 0
    for linea in sys.stdin.read().splitlines():
        anterior, nuevo, rama = linea.split()
        # Borrar una rama no agrega código
        if SIN_COMMIT.match(nuevo):
            continue
        nunca_vistos = commits_nunca_vistos(nuevo)
        for sha in commits_que_entran(anterior, nuevo):
            asunto = git("log", "-1", "--format=%s", sha).strip()[:60]
            try:
                datos = verificar_commit(sha, llave, filtros, usuario if sha in nunca_vistos else None)
                print(f"OK     {sha[:8]}  {datos['sub']:<16} {asunto}")
            except ReciboInvalido as error:
                fallidos += 1
                print(f"FALLA  {sha[:8]}  {error}  ({asunto})")

    if fallidos:
        print(f"Push rechazado: {fallidos} commit(s) sin un recibo de integridad válido.")
        return 1
    return 0


if __name__ == "__main__":
    # Saltos de línea LF: con CRLF (Windows) git muestra un "remote:" extra al final de cada línea
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    sys.exit(main())
