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

# Hash de ceros: indica una rama nueva (en el hash anterior) o una rama borrada (en el nuevo)
SIN_COMMIT = re.compile(r"^0+$")

# Causa probable de cada error del verificador, para quien recibe el rechazo
CAUSAS = (
    ("no tiene recibo", "El commit no pasó por el análisis de seguridad: se hizo con --no-verify, sin los hooks "
                        "instalados o con rebase, cherry-pick o squash."),
    ("pertenece a", "El recibo es de otra persona. Cada commit nuevo lo debe subir quien lo analizó."),
    ("no fue aprobado", "El análisis encontró vulnerabilidades en este código."),
    ("no se analizaron", "Hay archivos de código que quedaron fuera del análisis."),
    ("no indica qué archivos", "Hay archivos de código que quedaron fuera del análisis."),
    ("no coincide", "El código cambió después del análisis."),
    ("no es el que se analizó", "El código cambió después del análisis."),
    ("contra el padre", "El commit se modificó con --amend o se movió con rebase después del análisis."),
)
CAUSA_RECIBO_ALTERADO = "El recibo fue modificado o no lo emitió el servidor de análisis de este repositorio."

# Instrucciones que acompañan a todo rechazo
CORRECCION = """\
Ninguna rama se actualizó. Para corregirlo, rehacer los commits rechazados pasando por el análisis.
Si es solo el último commit:
    git reset --soft HEAD~1
    git commit -m "mensaje"
Y volver a hacer el push."""


def causa(error):
    # La primera causa cuyo texto aparece en el error; si ninguna coincide, el recibo fue alterado
    texto = str(error)
    return next((descripcion for clave, descripcion in CAUSAS if clave in texto), CAUSA_RECIBO_ALTERADO)


def commits_que_entran(anterior, nuevo):
    # Todos los commits que se incorporan a la rama, aunque ya existan en otra referencia del servidor:
    # por ejemplo los de un pull request desde un fork, que llegan sin pasar por este hook
    # Rama nueva: los commits que no están en ninguna rama existente
    if SIN_COMMIT.match(anterior):
        return git("rev-list", "--reverse", nuevo, "--not", "--branches").split()
    # Rama existente: los commits entre su estado actual y el nuevo
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

    fallidos = []
    for linea in sys.stdin.read().splitlines():
        anterior, nuevo, rama = linea.split()
        # Borrar una rama no agrega código
        if SIN_COMMIT.match(nuevo):
            continue
        nunca_vistos = commits_nunca_vistos(nuevo)
        for sha in commits_que_entran(anterior, nuevo):
            # Asunto del commit, recortado para la salida
            asunto = git("log", "-1", "--format=%s", sha).strip()[:60]
            try:
                # La identidad se exige solo a los commits nuevos para el servidor
                datos = verificar_commit(sha, llave, filtros, usuario if sha in nunca_vistos else None)
                print(f"OK     {sha[:8]}  {datos['sub']:<16} {asunto}")
            except ReciboInvalido as error:
                fallidos.append((sha, asunto, error))
                print(f"FALLA  {sha[:8]}  {error}  ({asunto})")

    # Código de salida distinto de 0: Git rechaza el push completo
    if not fallidos:
        return 0
    print()
    print(f"PUSH RECHAZADO por el control de seguridad: {len(fallidos)} commit(s) sin un recibo de análisis válido.")
    for sha, asunto, error in fallidos:
        print()
        print(f"  Commit:  {sha[:8]}  {asunto}")
        print(f"  Motivo:  {error}")
        print(f"  Causa:   {causa(error)}")
    print()
    print(CORRECCION)
    print()
    return 1


if __name__ == "__main__":
    # Saltos de línea LF: con CRLF (Windows) git muestra un "remote:" extra al final de cada línea
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    sys.exit(main())
