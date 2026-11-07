"""Hook de pre-commit: recolecta los cambios en staging para su análisis."""

import json
import sys

import git_cambios

MAX_BYTES_ARCHIVO = 100_000
MAX_BYTES_TOTAL = 500_000


def construir_paquete(rutas):
    return {
        "tree_hash": git_cambios.tree_hash(),
        **git_cambios.metadatos(),
        "archivos": [git_cambios.cambio_de_archivo(ruta) for ruta in rutas],
    }


def validar_tamano(paquete):
    errores = []
    total = 0
    for archivo in paquete["archivos"]:
        tamano = len(archivo["contenido"].encode("utf-8"))
        total += tamano
        if tamano > MAX_BYTES_ARCHIVO:
            errores.append(f"{archivo['ruta']}: {tamano} bytes (máximo {MAX_BYTES_ARCHIVO})")
    if total > MAX_BYTES_TOTAL:
        errores.append(f"Total del commit: {total} bytes (máximo {MAX_BYTES_TOTAL})")
    return errores


def main(rutas):
    if not rutas:
        return 0

    paquete = construir_paquete(rutas)

    # Lo que no se puede analizar no se aprueba (fail closed)
    errores = validar_tamano(paquete)
    if errores:
        print("Commit rechazado: el cambio supera el tamaño permitido para el análisis.")
        for error in errores:
            print(f"  {error}")
        print("Divide el cambio en commits más pequeños o excluye los archivos generados.")
        return 1

    print(json.dumps(paquete, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    # Evita que el hook falle en consolas de Windows que no soportan algunos caracteres
    sys.stdout.reconfigure(errors="replace")
    # pre-commit entrega como argumentos los archivos en staging que pasan los filtros de la configuración
    sys.exit(main(sys.argv[1:]))
