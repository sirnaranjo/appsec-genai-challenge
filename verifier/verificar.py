"""Verifica los recibos de integridad de uno o varios commits.

Uso:
    python verifier/verificar.py                      último commit
    python verifier/verificar.py abc123 HEAD~2        commits indicados
    python verifier/verificar.py origin/main..HEAD    rango de commits
Opciones:
    --llave RUTA      llave pública (por defecto la variable APPSEC_PUBLIC_KEY o keys/receipt_public.pem)
    --config RUTA     configuración de pre-commit con los filtros del hook (por defecto la del repositorio)
    --usuario LOGIN   exige que los recibos pertenezcan a ese usuario de GitHub
    --resumen RUTA    agrega una tabla en Markdown al archivo indicado (resumen de GitHub Actions)
"""

import argparse
import os
import re
import sys
from pathlib import Path

from recibos import ReciboInvalido, cargar_llave_publica, filtros_del_hook, git, verificar_commit

RAIZ = Path(__file__).resolve().parent.parent
SIN_COMMIT = re.compile(r"^0+$")


def leer_llave(ruta):
    if ruta:
        return cargar_llave_publica(Path(ruta).read_bytes())
    if os.environ.get("APPSEC_PUBLIC_KEY"):
        return cargar_llave_publica(os.environ["APPSEC_PUBLIC_KEY"].encode())
    return cargar_llave_publica((RAIZ / "keys" / "receipt_public.pem").read_bytes())


def commits_de(revisiones):
    commits = []
    for revision in revisiones:
        if ".." in revision:
            desde, hasta = revision.split("..", 1)
            # Un push que crea la rama no tiene commit anterior: se verifica solo el commit final
            if SIN_COMMIT.match(desde):
                commits.append(git("rev-parse", "--verify", f"{hasta}^{{commit}}").strip())
            else:
                commits += git("rev-list", "--reverse", revision).split()
        else:
            commits.append(git("rev-parse", "--verify", f"{revision}^{{commit}}").strip())
    return commits


def escribir_resumen(ruta, filas, fallidos):
    estado = f"❌ {fallidos} commit(s) sin un recibo válido" if fallidos else "✅ Todos los commits tienen un recibo válido"
    lineas = [f"## Recibos de integridad: {estado}", "", "| Commit | Resultado | Usuario | Asunto |", "|---|---|---|---|"]
    lineas += [f"| `{sha[:8]}` | {resultado} | {usuario} | {asunto.replace('|', '/')} |" for sha, resultado, usuario, asunto in filas]
    with open(ruta, "a", encoding="utf-8") as archivo:
        archivo.write("\n".join(lineas) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Verifica los recibos de integridad de los commits")
    parser.add_argument("revisiones", nargs="*", default=["HEAD"])
    parser.add_argument("--llave")
    parser.add_argument("--config", default=str(RAIZ / ".pre-commit-config.yaml"))
    parser.add_argument("--usuario")
    parser.add_argument("--resumen")
    argumentos = parser.parse_args()

    llave = leer_llave(argumentos.llave)
    filtros = filtros_del_hook(Path(argumentos.config))
    filas = []
    fallidos = 0
    for sha in commits_de(argumentos.revisiones):
        asunto = git("log", "-1", "--format=%s", sha).strip()[:60]
        try:
            datos = verificar_commit(sha, llave, filtros, argumentos.usuario)
            filas.append((sha, "OK", datos["sub"], asunto))
            print(f"OK     {sha[:8]}  {datos['sub']:<16} {asunto}")
        except ReciboInvalido as error:
            fallidos += 1
            filas.append((sha, f"FALLA: {error}", "", asunto))
            print(f"FALLA  {sha[:8]}  {error}  ({asunto})")

    if argumentos.resumen:
        escribir_resumen(argumentos.resumen, filas, fallidos)
    if fallidos:
        print(f"\n{fallidos} commit(s) sin un recibo de integridad válido.")
        return 1
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
sys.exit(0)
