"""Hooks del recibo de integridad.

    python hooks/recibo.py agregar <mensaje>   etapa commit-msg: agrega el recibo al mensaje del commit
    python hooks/recibo.py revisar             etapa post-commit: avisa si el commit no pasará la verificación
"""

import base64
import json
import re
import subprocess
import sys

import git_cambios

TRAILER = "AppSec-Receipt"
PATRON_TRAILER = re.compile(rf"^{TRAILER}:\s*(\S+)\s*$", re.MULTILINE)


def contenido_recibo(recibo):
    # El cliente solo lee el contenido; la firma la verifica el verificador con la llave pública
    cuerpo = recibo.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(cuerpo + "=" * (-len(cuerpo) % 4)))


def problema_del_ultimo_commit():
    encontrados = PATRON_TRAILER.findall(git_cambios.git("log", "-1", "--format=%B"))
    if not encontrados:
        return "no tiene recibo de análisis (por ejemplo, porque se usó --no-verify)"

    datos = contenido_recibo(encontrados[-1])
    if datos.get("tree") != git_cambios.git("rev-parse", "HEAD^{tree}").strip():
        return "tiene un contenido distinto al analizado"
    padres = git_cambios.git("log", "-1", "--format=%P").split()
    base = git_cambios.git("rev-parse", f"{padres[0]}^{{tree}}").strip() if padres else None
    if datos.get("base") != base:
        return "se analizó contra otro commit (por ejemplo, porque se usó --amend)"
    return None


def revisar_ultimo_commit():
    # post-commit corre incluso con --no-verify y no puede deshacer el commit:
    # avisa en el momento lo que el verificador del repositorio remoto va a rechazar
    problema = problema_del_ultimo_commit()
    if not problema:
        return 0
    print(f"Atención: el último commit {problema}.")
    print("No pasará la verificación de integridad en el repositorio remoto. Para corregirlo, si aún no lo subiste:")
    print("    git reset --soft HEAD~1")
    print('    git commit -m "mensaje"')
    return 1


def agregar_recibo(archivo_mensaje):
    pendiente = git_cambios.ruta_recibo_pendiente()
    if not pendiente.exists():
        print("Commit rechazado: no hay un recibo de análisis para este commit.")
        print("Verifica que los hooks estén instalados con: pre-commit install")
        return 1

    recibo = pendiente.read_text(encoding="utf-8").strip()
    pendiente.unlink()

    # El recibo debe corresponder exactamente al contenido que se va a guardar
    if contenido_recibo(recibo).get("tree") != git_cambios.tree_hash():
        print("Commit rechazado: el contenido en staging cambió después del análisis. Vuelve a hacer el commit.")
        return 1

    # replace: si el mensaje ya trae un AppSec-Receipt escrito a mano, se sustituye por el real
    subprocess.run(
        ["git", "interpret-trailers", "--in-place", "--if-exists", "replace", "--trailer", f"{TRAILER}: {recibo}", archivo_mensaje],
        check=True,
    )
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.argv[1] == "revisar":
        sys.exit(revisar_ultimo_commit())
    sys.exit(agregar_recibo(sys.argv[2]))
