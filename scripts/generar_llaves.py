"""Genera el par de llaves Ed25519 con el que el servidor firma los recibos de integridad.

La llave privada solo debe existir en el servidor. La pública se usa para verificar los recibos.
Uso:
    python scripts/generar_llaves.py
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CARPETA = Path(__file__).resolve().parent.parent / "keys"
PRIVADA = CARPETA / "receipt_private.pem"
PUBLICA = CARPETA / "receipt_public.pem"


def main():
    # No se sobrescribe una llave existente: los recibos ya emitidos dejarían de verificarse
    if PRIVADA.exists():
        print(f"Ya existe {PRIVADA}. Bórrala manualmente si de verdad quieres reemplazarla.")
        return 1

    llave = Ed25519PrivateKey.generate()
    CARPETA.mkdir(exist_ok=True)
    # Formatos PEM estándar. Sin contraseña: el servidor la carga al iniciar sin intervención
    PRIVADA.write_bytes(
        llave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    PUBLICA.write_bytes(
        llave.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )

    print(f"Llave privada: {PRIVADA}")
    print(f"Llave pública: {PUBLICA}")
    print()
    # La pública se muestra para copiarla en la variable APPSEC_PUBLIC_KEY de GitHub
    print(PUBLICA.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
