"""Hook de pre-commit: envía los cambios en staging al servidor de análisis de seguridad.

Flujo:
1. Comprueba que haya una sesión iniciada (token OAuth guardado con hooks/login.py).
2. Arma el paquete con los diffs en staging y las huellas del contenido (tree del commit y de su padre).
3. Lo envía al servidor, que valida la identidad, analiza con el LLM y decide si se aprueba.
4. Muestra el resultado. Si se aprueba, guarda el recibo firmado para el hook commit-msg.
Cualquier falla (sin sesión, cambio demasiado grande, servidor caído) rechaza el commit.
"""

import sys

import autenticacion
import cliente_api
import git_cambios
import presentacion

# Límites por archivo y por commit, los mismos que aplica el servidor (server/modelos.py)
MAX_BYTES_ARCHIVO = 100_000
MAX_BYTES_TOTAL = 500_000


def construir_paquete(rutas):
    # tree_hash identifica el contenido exacto del commit antes de que exista; el servidor lo
    # incluye en el recibo y el verificador lo compara con el commit que llega al repositorio
    return {
        "tree_hash": git_cambios.tree_hash(),
        # tree del padre y datos informativos (rama, commit padre, repositorio y autor)
        **git_cambios.metadatos(),
        "archivos": [git_cambios.cambio_de_archivo(ruta) for ruta in rutas],
    }


def validar_tamano(paquete):
    # El servidor vuelve a validar estos límites; aquí solo se avisa antes de enviar
    errores = []
    total = 0
    for archivo in paquete["archivos"]:
        # Se mide en bytes: un carácter con tilde o un emoji ocupa más de uno
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

    # La decisión la toma el servidor según la severidad de los hallazgos; el cliente solo la aplica.
    # El texto que viene del LLM se limpia antes de mostrarlo (ver presentacion.py)
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
