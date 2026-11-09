"""Análisis determinístico previo al LLM.

No usa IA, así que no se puede manipular con texto:
- Detecta intentos de dar instrucciones al revisor automático y caracteres Unicode engañosos.
- Señala patrones peligrosos conocidos; se le indican al LLM y se comparan con su respuesta.
"""

import re
from dataclasses import dataclass

from server.modelos import Hallazgo

# Va en el campo owasp de los hallazgos de manipulación, que no son una categoría del OWASP Top 10
MANIPULACION = "Manipulacion del analisis"
# Los títulos indican el origen: así se distinguen de los hallazgos del LLM cuando ambos coinciden
TITULO_INVISIBLES = "Caracteres Unicode invisibles o de control de dirección (detección por reglas)"
TITULO_INSTRUCCIONES = "Instrucciones dirigidas al revisor automático (detección por reglas)"
TITULO_RUTA = "Nombre de archivo con instrucciones para el revisor (detección por reglas)"
# Encabezado de cada bloque de un diff ("@@ -10,3 +12,4 @@"); se captura la línea inicial en el archivo nuevo
PATRON_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# Unicode que oculta o reordena el texto (Trojan Source, CVE-2021-42574) o parte palabras sin verse:
# espacios y uniones de ancho cero, BOM y controles de dirección (202A-202E y 2066-2069)
INVISIBLES = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, *range(0x202A, 0x202F), *range(0x2066, 0x206A)]
CARACTERES_INVISIBLES = re.compile("[" + "".join(map(chr, INVISIBLES)) + "]")
BOM = chr(0xFEFF)

# Frases dirigidas al revisor. Los patrones usan clases de caracteres y no el texto literal,
# así este archivo no se detecta a sí mismo
FRASES_MANIPULACION = [
    # Orden de pasar por alto las reglas del revisor
    r"ignor\w*\s+(\w+\s+){0,3}(instrucci|instruction|indicaci|regla|rule)",
    # Orden de descartar lo indicado antes
    r"(disregard|olvid\w*|forget)\s+(\w+\s+){0,3}(instrucci|instruction|previous|anterior|above|regla|rule)",
    # Pedir que no se reporte algo
    r"(no\s+reportes|do\s+not\s+report|don'?t\s+report|no\s+informes)",
    # Pedir una respuesta sin resultados
    r"(hallazgos|findings)\s+(vac[ií]\w*|empty)|(lista|list)\s+(de\s+)?(hallazgos|findings)\s+(vac[ií]\w*|empty)",
    # Respuesta JSON preescrita sin hallazgos
    r"[\"']?(hallazgos|findings)[\"']?\s*:\s*\[\s*\]",
    # Pedir la aprobación del código
    r"(aprueb\w*|approve)\s+(este|el|this|the)\s+(commit|cambio|c[oó]digo|change|code|pull\s+request)",
    # Mensajes dirigidos al revisor. Solo destinatarios de revisión: "mensaje para el modelo" es habitual en aplicaciones que usan IA
    r"(nota|note|mensaje|message|aviso)\s+(para|to|for)\s+(el\s+|la\s+|the\s+)?(revisor|reviewer|analizador|analyzer|auditor|esc[aá]ner|scanner)\b",
    # Abrir o cerrar la etiqueta de cambios del prompt
    r"</?\s*cambios",
    # Etiquetas de sistema o de instrucciones
    r"</?\s*(system|instrucciones|instructions)\s*>",
    # Anunciar otras órdenes para el revisor
    r"(nuevas|new)\s+(instrucciones|instructions)",
    # Asignar otro rol al revisor
    r"(you\s+are\s+now|ahora\s+eres|act[uú]a\s+como\s+(un|una)|act\s+as\s+an?)\b",
    # Comentarios que simulan mensajes del sistema o del asistente
    r"(#|//|/\*|\*)\s*(system|assistant|sistema|asistente)\s*:",
    # Afirmar una revisión de seguridad previa
    r"(ya\s+fue\s+(auditad|revisad|aprobad)|already\s+(been\s+)?(audited|reviewed|approved)|approved\s+by\s+(the\s+)?security)",
]
PATRON_MANIPULACION = re.compile("|".join(f"(?:{frase})" for frase in FRASES_MANIPULACION), re.IGNORECASE)


# Patrón peligroso encontrado en una línea agregada
@dataclass(frozen=True)
class Senal:
    archivo: str
    linea: int
    owasp: str
    descripcion: str
    confianza: str


# (patrón, categoría OWASP, descripción, confianza). Confianza alta: casi siempre vulnerable con datos variables
PATRONES_PELIGROSOS = [
    (r"\bos\.(system|popen)\s*\(", "A03:2021-Injection", "ejecución de comandos con la shell (os.system/os.popen)", "alta"),
    (r"\bsubprocess\.\w+\(.*shell\s*=\s*True", "A03:2021-Injection", "subprocess con shell=True", "alta"),
    (r"(?<![\w.])(eval|exec)\s*\(", "A03:2021-Injection", "ejecución dinámica de código (eval/exec)", "alta"),
    (r"\.execute\w*\s*\(\s*f[\"']", "A03:2021-Injection", "consulta SQL construida con f-string", "alta"),
    (r"\.execute\w*\s*\(\s*[\"'][^\"']*[\"']\s*(\+|%(?!s?\s*,)|\.format\()", "A03:2021-Injection", "consulta SQL construida por concatenación", "alta"),
    (r"\bchild_process\.exec(Sync)?\s*\(|\bexecSync\s*\(", "A03:2021-Injection", "ejecución de comandos en Node.js", "alta"),
    (r"\.innerHTML\s*=|dangerouslySetInnerHTML|render_template_string\s*\(", "A03:2021-Injection", "HTML generado sin escapar", "media"),
    (r"\bpickle\.loads?\s*\(|\bmarshal\.loads\s*\(", "A08:2021-Software and Data Integrity Failures", "deserialización con pickle/marshal", "alta"),
    (r"\byaml\.load\s*\((?![^)]*SafeLoader)", "A08:2021-Software and Data Integrity Failures", "yaml.load sin SafeLoader", "alta"),
    (r"\bhashlib\.(md5|sha1)\s*\(", "A02:2021-Cryptographic Failures", "hash débil (MD5/SHA1)", "media"),
    (r"\bverify\s*=\s*False\b", "A02:2021-Cryptographic Failures", "verificación TLS desactivada", "media"),
    (r"(?i)\b\w*(api_?key|secret|password|passwd|token)\w*\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']", "A07:2021-Identification and Authentication Failures", "credencial escrita en el código", "media"),
    (r"\brequests\.(get|post|put|delete|head|request)\s*\(\s*(?![\"'])\w", "A10:2021-Server-Side Request Forgery", "solicitud HTTP a una URL variable", "media"),
    (r"\burlopen\s*\(\s*(?![\"'])\w", "A10:2021-Server-Side Request Forgery", "solicitud HTTP a una URL variable", "media"),
]
PATRONES_COMPILADOS = [(re.compile(patron), owasp, descripcion, confianza) for patron, owasp, descripcion, confianza in PATRONES_PELIGROSOS]


def lineas_agregadas(archivo):
    # Devuelve (número de línea en el archivo nuevo, texto) de las líneas nuevas: el código eliminado no cuenta
    # Un archivo completo es todo nuevo
    if archivo.tipo == "completo":
        yield from enumerate(archivo.contenido.splitlines(), start=1)
        return
    numero = None
    for linea in archivo.contenido.splitlines():
        encabezado = PATRON_HUNK.match(linea)
        if encabezado:
            # Nuevo bloque: la numeración sigue desde la línea que indica el encabezado
            numero = int(encabezado.group(1))
        elif numero is None or linea.startswith(("+++", "---", "\\")):
            # Antes del primer bloque, nombres de archivo y el aviso "\ No newline at end of file"
            continue
        elif linea.startswith("+"):
            yield numero, linea[1:]
            numero += 1
        elif not linea.startswith("-"):
            # Línea de contexto: existe en el archivo nuevo. Las eliminadas (-) no avanzan la numeración
            numero += 1


def hallazgo_manipulacion(archivo, linea, titulo, riesgo):
    return Hallazgo(
        owasp=MANIPULACION,
        titulo=titulo,
        archivo=archivo,
        linea=linea,
        severidad="ALTA",
        riesgo=riesgo,
        solucion="Eliminar el texto o los caracteres y no incluir instrucciones dirigidas a herramientas de revisión.",
    )


def detectar_manipulacion(archivos):
    hallazgos = []
    for archivo in archivos:
        # La ruta también la controla quien hace el commit y llega al prompt
        if PATRON_MANIPULACION.search(CARACTERES_INVISIBLES.sub("", archivo.ruta)):
            hallazgos.append(hallazgo_manipulacion(
                archivo.ruta, None, TITULO_RUTA,
                "La ruta del archivo contiene texto que intenta dar órdenes al análisis automático.",
            ))
        for numero, texto in lineas_agregadas(archivo):
            # El BOM al inicio del archivo es legítimo
            visible = texto[1:] if numero == 1 and texto.startswith(BOM) else texto
            if CARACTERES_INVISIBLES.search(visible):
                hallazgos.append(hallazgo_manipulacion(
                    archivo.ruta, numero, TITULO_INVISIBLES,
                    "Estos caracteres pueden ocultar código a quien lo revisa o alterar cómo se lee (Trojan Source, CVE-2021-42574).",
                ))
            # Se quitan los invisibles antes de buscar, para detectar palabras partidas con ellos
            if PATRON_MANIPULACION.search(CARACTERES_INVISIBLES.sub("", visible)):
                hallazgos.append(hallazgo_manipulacion(
                    archivo.ruta, numero, TITULO_INSTRUCCIONES,
                    "El código contiene texto que intenta cambiar el resultado del análisis de seguridad.",
                ))
    return hallazgos


def detectar_senales(archivos):
    senales = []
    for archivo in archivos:
        for numero, texto in lineas_agregadas(archivo):
            for patron, owasp, descripcion, confianza in PATRONES_COMPILADOS:
                if patron.search(texto):
                    senales.append(Senal(archivo.ruta, numero, owasp, descripcion, confianza))
    return senales


def categoria(owasp):
    # "A03:2021-Injection" -> "A03"
    return owasp.split(":")[0]


def contradicciones(senales, hallazgos):
    # Señal de confianza alta que el LLM no reportó: puede ser un uso seguro o un análisis manipulado.
    # Se advierte sin bloquear, para no generar falsos positivos, y queda registrado
    # Se compara por archivo y categoría, no por línea: el LLM puede ubicar el problema en otra línea
    reportadas = {(h.archivo, categoria(h.owasp)) for h in hallazgos}
    advertencias = []
    for senal in senales:
        clave = (senal.archivo, categoria(senal.owasp))
        if senal.confianza == "alta" and clave not in reportadas:
            # Una sola advertencia por archivo y categoría
            reportadas.add(clave)
            advertencias.append(Hallazgo(
                owasp=senal.owasp,
                titulo=f"Patrón sensible no confirmado: {senal.descripcion}",
                archivo=senal.archivo,
                linea=senal.linea,
                severidad="BAJA",
                riesgo="El análisis determinístico detectó este patrón y el análisis con IA no lo reportó. Puede ser un uso seguro o un intento de evadir el análisis.",
                solucion="Confirma que los datos que llegan a esta línea son constantes o están validados.",
            ))
    return advertencias
