"""Hook de pre-commit para el análisis de seguridad de los archivos en staging."""

import sys

PATRON = "password"


def buscar_coincidencias(ruta):
    hallazgos = []
    with open(ruta, encoding="utf-8", errors="ignore") as archivo:
        for numero, linea in enumerate(archivo, start=1):
            if PATRON in linea.lower():
                hallazgos.append((numero, linea.strip()))
    return hallazgos


def main(archivos):
    encontrado = False
    for ruta in archivos:
        for numero, linea in buscar_coincidencias(ruta):
            print(f"{ruta}:{numero}: {linea}")
            encontrado = True

    # Un código de salida distinto de 0 hace que git cancele el commit
    if encontrado:
        print("Commit rechazado: posibles credenciales en el código.")
        return 1
    return 0


if __name__ == "__main__":
    # pre-commit entrega como argumentos los archivos que están en staging
    sys.exit(main(sys.argv[1:]))
