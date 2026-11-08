"""Verifica los recibos de integridad de uno o varios commits.

Uso:
    python verifier/verificar.py                      último commit
    python verifier/verificar.py abc123 HEAD~2        commits indicados
    python verifier/verificar.py origin/main..HEAD    rango de commits
Opciones:
    --llave RUTA      llave pública (por defecto la variable APPSEC_PUBLIC_KEY o keys/receipt_public.pem)
    --usuario LOGIN   exige que los recibos pertenezcan a ese usuario de GitHub
"""

import argparse
import os
import sys
from pathlib import Path

from recibos import ReciboInvalido, cargar_llave_publica, git, verificar_commit

LLAVE_POR_DEFECTO = Path(__file__).resolve().parent.parent / "keys" / "receipt_public.pem"


def leer_llave(ruta):
    if ruta:
        return cargar_llave_publica(Path(ruta).read_bytes())
    if os.environ.get("APPSEC_PUBLIC_KEY"):
        return cargar_llave_publica(os.environ["APPSEC_PUBLIC_KEY"].encode())
    return cargar_llave_publica(LLAVE_POR_DEFECTO.read_bytes())


def commits_de(revisiones):
    commits = []
    for revision in revisiones:
        if ".." in revision:
            commits += git("rev-list", "--reverse", revision).split()
        else:
            commits.append(git("rev-parse", "--verify", f"{revision}^{{commit}}"))
    return commits


def main():
    parser = argparse.ArgumentParser(description="Verifica los recibos de integridad de los commits")
    parser.add_argument("revisiones", nargs="*", default=["HEAD"])
    parser.add_argument("--llave")
    parser.add_argument("--usuario")
    argumentos = parser.parse_args()

    llave = leer_llave(argumentos.llave)
    fallidos = 0
    for sha in commits_de(argumentos.revisiones):
        asunto = git("log", "-1", "--format=%s", sha)[:50]
        try:
            datos = verificar_commit(sha, llave, argumentos.usuario)
            print(f"OK     {sha[:8]}  {datos['sub']:<16} {asunto}")
        except ReciboInvalido as error:
            fallidos += 1
            print(f"FALLA  {sha[:8]}  {error}  ({asunto})")

    if fallidos:
        print(f"\n{fallidos} commit(s) sin un recibo de integridad válido.")
        return 1
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
