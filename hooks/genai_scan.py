"""Hook de pre-commit: envía los cambios en staging al servidor de análisis de seguridad."""

import sys

import autenticacion
import cliente_api
import git_cambios
import presentacion

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
    # Un recibo de un intento anterior nunca debe llegar a este commit
    pendiente = git_cambios.ruta_recibo_pendiente()
    pendiente.unlink(missing_ok=True)

    # El hook corre en todos los commits, aunque no cambien código, porque todos necesitan recibo.
    # El hook no puede pedir el login porque pre-commit captura la salida; se hace con login.py
    token = autenticacion.token_guardado()
    if not token:
        presentacion.mostrar_error(f"Commit rechazado: no hay una sesión iniciada. {cliente_api.MENSAJE_LOGIN}")
        return 1

    paquete = construir_paquete(rutas)

    # Lo que no se puede analizar no se aprueba (fail closed)
    errores = validar_tamano(paquete)
    if errores:
        errores.append("Divide el cambio en commits más pequeños o excluye los archivos generados.")
        presentacion.mostrar_error("Commit rechazado: el cambio supera el tamaño permitido para el análisis.", errores)
        return 1

    try:
        resultado = cliente_api.solicitar_analisis(paquete, token)
    except cliente_api.ErrorServidor as error:
        # Si el servidor no responde el commit tampoco se aprueba
        presentacion.mostrar_error(f"Commit rechazado: {error}")
        return 1

    presentacion.mostrar_resultado(resultado)
    if not resultado["aprobado"]:
        return 1

    # El hook commit-msg lo agrega al mensaje del commit
    pendiente.write_text(resultado["recibo"], encoding="utf-8")
    return 0


if __name__ == "__main__":
    # pre-commit reenvía esta salida a la terminal como UTF-8; sin esto las tildes se ven mal en Windows
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # pre-commit entrega como argumentos los archivos en staging que pasan los filtros de la configuración
    sys.exit(main(sys.argv[1:]))
