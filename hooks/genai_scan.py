"""Hook de pre-commit: envía los cambios en staging al servidor de análisis de seguridad."""

import sys

import cliente_api
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


def mostrar_hallazgo(hallazgo):
    print()
    print(f"[{hallazgo['severidad']}] {hallazgo['titulo']} ({hallazgo['owasp']})")
    print(f"  Archivo: {hallazgo['archivo']}" + (f", línea {hallazgo['linea']}" if hallazgo["linea"] else ""))
    print(f"  Riesgo: {hallazgo['riesgo']}")
    print(f"  Solución: {hallazgo['solucion']}")
    if hallazgo["codigo_sugerido"]:
        print("  Código sugerido:")
        for linea in hallazgo["codigo_sugerido"].splitlines():
            print(f"    {linea}")


def mostrar_resultado(resultado):
    hallazgos = resultado["hallazgos"]
    if resultado["aprobado"] and not hallazgos:
        print(f"Análisis aprobado. Id: {resultado['id_analisis']}")
        return

    if resultado["aprobado"]:
        print(f"Análisis aprobado con advertencias: {len(hallazgos)}")
    else:
        print(f"Commit rechazado. Vulnerabilidades encontradas: {len(hallazgos)}")
    for hallazgo in hallazgos:
        mostrar_hallazgo(hallazgo)
    print()
    print(f"Id del análisis: {resultado['id_analisis']}")


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

    try:
        resultado = cliente_api.solicitar_analisis(paquete)
    except cliente_api.ErrorServidor as error:
        # Si el servidor no responde el commit tampoco se aprueba
        print(f"Commit rechazado: {error}")
        return 1

    mostrar_resultado(resultado)
    return 0 if resultado["aprobado"] else 1


if __name__ == "__main__":
    # Evita que el hook falle en consolas de Windows que no soportan algunos caracteres
    sys.stdout.reconfigure(errors="replace")
    # pre-commit entrega como argumentos los archivos en staging que pasan los filtros de la configuración
    sys.exit(main(sys.argv[1:]))
