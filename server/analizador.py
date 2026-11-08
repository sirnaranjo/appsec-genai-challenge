"""Análisis de seguridad de los cambios recibidos."""

import re

from server.modelos import Hallazgo, SolicitudAnalisis

PATRON_OS_SYSTEM = re.compile(r"\bos\.system\s*\(")


def analizar(solicitud: SolicitudAnalisis) -> list[Hallazgo]:
    # Análisis simulado para probar el flujo; en la Fase 4 se reemplaza por el LLM
    hallazgos = []
    for archivo in solicitud.archivos:
        for linea in archivo.contenido.splitlines():
            # En un diff las líneas que empiezan con "-" son código eliminado
            if linea.startswith("-"):
                continue
            if PATRON_OS_SYSTEM.search(linea):
                hallazgos.append(
                    Hallazgo(
                        owasp="A03:2021-Injection",
                        titulo="Posible inyección de comandos",
                        archivo=archivo.ruta,
                        severidad="ALTA",
                        riesgo="La función os.system ejecuta comandos del sistema a través de una shell.",
                        solucion="Usar subprocess.run con una lista de argumentos y shell=False.",
                    )
                )
    return hallazgos
