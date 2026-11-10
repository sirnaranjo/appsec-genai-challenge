"""Demostración del hook pre-receive: un servidor Git que rechaza el push de commits sin recibo válido.

Crea en una carpeta temporal un repositorio "desnudo" que hace de servidor Git (una copia de este
repositorio con verifier/pre_receive.py instalado como hook) y un clon de trabajo con los hooks de
pre-commit. Luego intenta:
1. Subir un commit hecho con --no-verify: el servidor rechaza el push.
2. Subir un commit que pasó por el análisis: el servidor acepta el push.

Requiere el servidor de análisis en ejecución, una sesión iniciada (hooks/login.py) y la llave
pública en keys/receipt_public.pem. Uso:
    python scripts/demo_pre_receive.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from dotenv import dotenv_values

RAIZ = Path(__file__).resolve().parent.parent
LLAVE = RAIZ / "keys" / "receipt_public.pem"


def pasar_url_del_servidor():
    # El repositorio temporal no tiene .env: el hook recibe por el entorno la URL del servidor de análisis
    url = dotenv_values(RAIZ / ".env").get("APPSEC_SERVER_URL")
    if url:
        os.environ.setdefault("APPSEC_SERVER_URL", url)


def git(carpeta, *args, salida=False):
    return subprocess.run(["git", *args], cwd=carpeta, check=not salida, capture_output=not salida)


def preparar_servidor(carpeta):
    servidor = carpeta / "servidor.git"
    # --bare: repositorio sin carpeta de trabajo, como el de un servidor
    git(carpeta, "clone", "-q", "--bare", str(RAIZ), str(servidor))
    # Git ejecuta los hooks con sh, también en Windows: se usan rutas con barras normales.
    # Sin --usuario-desde: en la demostración no hay usuarios autenticados
    hook = servidor / "hooks" / "pre-receive"
    hook.write_text(
        "#!/bin/sh\n"
        f'exec "{Path(sys.executable).as_posix()}" "{(RAIZ / "verifier" / "pre_receive.py").as_posix()}" '
        f'--llave "{LLAVE.as_posix()}"\n',
        newline="\n",
    )
    hook.chmod(0o755)
    return servidor


def preparar_clon(carpeta, servidor):
    clon = carpeta / "clon"
    git(carpeta, "clone", "-q", str(servidor), str(clon))
    git(clon, "config", "user.name", "Demo")
    git(clon, "config", "user.email", "demo@example.com")
    subprocess.run([sys.executable, "-m", "pre_commit", "install"], cwd=clon, check=True, capture_output=True)
    return clon


def intentar_push(clon, titulo, archivo, contenido, sin_analisis):
    print(f"\n{'=' * 100}\n  {titulo}\n{'=' * 100}", flush=True)
    (clon / archivo).write_text(contenido)
    git(clon, "add", archivo)
    opciones = ["--no-verify"] if sin_analisis else []
    print(f"$ git commit {' '.join([*opciones, '-m'])} \"Agrega {archivo}\"", flush=True)
    git(clon, "commit", *opciones, "-m", f"Agrega {archivo}", salida=True)

    # Se sube la rama actual, sea cual sea su nombre
    print("\n$ git push origin HEAD", flush=True)
    aceptado = git(clon, "push", "origin", "HEAD", salida=True).returncode == 0
    print(f"\nResultado: {'PUSH ACEPTADO' if aceptado else 'PUSH RECHAZADO'}", flush=True)
    # Si se rechazó, el clon vuelve al estado del servidor para el siguiente intento
    if not aceptado:
        git(clon, "reset", "-q", "--hard", "@{upstream}")
    return aceptado


def main():
    pasar_url_del_servidor()
    if not LLAVE.exists():
        print(f"No se encontró la llave pública en {LLAVE}. Genérala con: python scripts/generar_llaves.py")
        return 1

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directorio:
        carpeta = Path(directorio)
        clon = preparar_clon(carpeta, preparar_servidor(carpeta))
        rechazado = not intentar_push(
            clon, "Commit hecho con --no-verify", "comandos.py",
            "import os\n\n\ndef ejecutar(cmd):\n    os.system(cmd)\n", sin_analisis=True,
        )
        aceptado = intentar_push(
            clon, "Commit analizado y aprobado", "calculos.py",
            "def sumar(a, b):\n    return a + b\n", sin_analisis=False,
        )

    print(f"\n{'=' * 100}\n  Resumen\n{'=' * 100}")
    print(f"  Push sin análisis:  {'rechazado' if rechazado else 'ACEPTADO (inesperado)'}")
    print(f"  Push con recibo:    {'aceptado' if aceptado else 'RECHAZADO (inesperado)'}")
    return 0 if rechazado and aceptado else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
