"""Presentación de los resultados del análisis en la terminal del desarrollador."""

import re

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

# pre-commit captura la salida del hook y la muestra después, por eso se fuerzan los colores ANSI
# (en Windows rich usaría el modo de consola antiguo, que no funciona a través de pre-commit)
consola = Console(force_terminal=True, legacy_windows=False, color_system="standard", width=100, highlight=False)

SEVERIDADES = ["BAJA", "MEDIA", "ALTA", "CRITICA"]
COLORES = {"CRITICA": "bold red", "ALTA": "red", "MEDIA": "yellow", "BAJA": "cyan"}

# Caracteres de control salvo salto de línea y tabulación
CARACTERES_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def limpiar(valor):
    # El texto del LLM puede repetir código del atacante: se quitan las secuencias de escape
    # que podrían manipular la terminal (cambiar el título, borrar la pantalla, simular otra salida)
    if isinstance(valor, str):
        return CARACTERES_CONTROL.sub("", valor)
    return valor


def bloquea(hallazgo, severidad_bloqueo):
    return SEVERIDADES.index(hallazgo["severidad"]) >= SEVERIDADES.index(severidad_bloqueo)


def panel_hallazgo(hallazgo, es_bloqueante):
    # El texto que viene del LLM se maneja como Text y no como markup de rich,
    # así que corchetes o secuencias de control dentro del código no alteran la salida
    color = COLORES[hallazgo["severidad"]]
    ubicacion = hallazgo["archivo"] + (f", línea {hallazgo['linea']}" if hallazgo["linea"] else "")
    partes = [
        Text.assemble(("Severidad: ", "bold"), (hallazgo["severidad"], color), ("    OWASP: ", "bold"), hallazgo["owasp"]),
        Text.assemble(("Ubicación: ", "bold"), ubicacion),
        Text(),
        Text.assemble(("Riesgo: ", "bold"), hallazgo["riesgo"]),
        Text(),
        Text.assemble(("Solución sugerida: ", "bold"), hallazgo["solucion"]),
    ]
    if hallazgo["codigo_sugerido"]:
        lexer = Syntax.guess_lexer(hallazgo["archivo"], hallazgo["codigo_sugerido"])
        partes += [
            Text(),
            Text("Código sugerido:", style="bold"),
            Syntax(hallazgo["codigo_sugerido"], lexer, theme="ansi_dark", background_color="default", word_wrap=True),
        ]

    if es_bloqueante:
        titulo = Text(f"🚨 Vulnerabilidad detectada: {hallazgo['titulo']}", style=color)
    else:
        titulo = Text(f"▲ Advertencia: {hallazgo['titulo']}", style=color)
    return Panel(Group(*partes), title=titulo, title_align="left", border_style=color, padding=(1, 2))


def mostrar_resultado(resultado):
    limpios = [{campo: limpiar(valor) for campo, valor in h.items()} for h in resultado["hallazgos"]]
    hallazgos = sorted(limpios, key=lambda h: SEVERIDADES.index(h["severidad"]), reverse=True)
    bloqueantes = [h for h in hallazgos if bloquea(h, resultado["severidad_bloqueo"])]

    if not resultado["aprobado"]:
        consola.print(Text(f"✗ Commit rechazado: vulnerabilidades detectadas: {len(bloqueantes)}", style="bold red"))
    elif hallazgos:
        consola.print(Text(f"✓ Análisis aprobado con advertencias: {len(hallazgos)}", style="bold green"))
    else:
        consola.print(Text("✓ Análisis aprobado", style="bold green"))

    for hallazgo in hallazgos:
        consola.print(panel_hallazgo(hallazgo, hallazgo in bloqueantes))

    consola.print(
        Text(
            f"Análisis {resultado['id_analisis']} · {resultado['usuario']} · {resultado['modelo']} · {resultado['version_prompt']}",
            style="dim",
        )
    )


def mostrar_error(mensaje, detalles=()):
    consola.print(Text(f"✗ {limpiar(mensaje)}", style="bold red"))
    for detalle in detalles:
        consola.print(Text(f"  {limpiar(detalle)}"))
