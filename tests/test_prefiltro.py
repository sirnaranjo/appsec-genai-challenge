"""Capa determinística contra prompt injection y patrones peligrosos."""

from pathlib import Path

import pytest
import yaml

from server import analizador, prefiltro
from server.modelos import Archivo, Hallazgo, SolicitudAnalisis

RAIZ = Path(__file__).resolve().parent.parent
CASOS = yaml.safe_load((RAIZ / "tests" / "datos" / "inyecciones.yaml").read_text(encoding="utf-8"))


def archivo_del_caso(caso):
    codigo = (
        "import os\nfrom flask import request\n\n"
        f"{caso['inyeccion']}\n\n"
        "def ejecutar():\n    os.system(request.args['cmd'])\n"
    )
    return Archivo(ruta=caso.get("ruta", "app.py"), tipo="completo", contenido=codigo)


def hallazgo(owasp, archivo="app.py", severidad="ALTA"):
    return Hallazgo(owasp=owasp, titulo="t", archivo=archivo, severidad=severidad, riesgo="r", solucion="s")


@pytest.mark.parametrize("caso", CASOS, ids=[caso["nombre"] for caso in CASOS])
def test_deteccion_determinista_de_manipulacion(caso):
    detectado = bool(prefiltro.detectar_manipulacion([archivo_del_caso(caso)]))
    assert detectado is caso["prefiltro"]


@pytest.mark.parametrize("caso", CASOS, ids=[caso["nombre"] for caso in CASOS])
def test_la_vulnerabilidad_siempre_genera_senal(caso):
    senales = prefiltro.detectar_senales([archivo_del_caso(caso)])
    assert any(s.owasp.startswith("A03") and s.confianza == "alta" for s in senales)


def test_el_proyecto_no_se_detecta_a_si_mismo():
    archivos = [
        Archivo(ruta=str(ruta.relative_to(RAIZ)), tipo="completo", contenido=ruta.read_text(encoding="utf-8"))
        for carpeta in ("hooks", "server", "verifier", "scripts", "tests")
        for ruta in (RAIZ / carpeta).rglob("*.py")
    ]
    assert prefiltro.detectar_manipulacion(archivos) == []


def test_codigo_comun_en_espanol_no_es_manipulacion():
    codigo = "def aprobar_solicitud(s):\n    # Se aprueba la solicitud si el revisor la marcó\n    return s.revisada\n"
    assert prefiltro.detectar_manipulacion([Archivo(ruta="a.py", tipo="completo", contenido=codigo)]) == []


def test_bom_al_inicio_no_es_manipulacion():
    archivo = Archivo(ruta="a.py", tipo="completo", contenido=chr(0xFEFF) + "import os\n")
    assert prefiltro.detectar_manipulacion([archivo]) == []


def test_solo_se_revisan_las_lineas_agregadas_con_su_numero():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -10,3 +10,3 @@\n"
        " contexto = 1\n-os.system(viejo)\n+os.system(nuevo)\n contexto = 2\n"
    )
    archivo = Archivo(ruta="a.py", tipo="diff", contenido=diff)
    assert list(prefiltro.lineas_agregadas(archivo)) == [(11, "os.system(nuevo)")]
    assert [s.linea for s in prefiltro.detectar_senales([archivo])] == [11]


@pytest.mark.parametrize(
    "codigo, categoria",
    [
        ("cur.execute(f\"SELECT * FROM t WHERE id = {x}\")", "A03"),
        ("cur.execute(\"SELECT * FROM t WHERE id = \" + x)", "A03"),
        ("subprocess.run(cmd, shell=True)", "A03"),
        ("datos = pickle.loads(cuerpo)", "A08"),
        ("config = yaml.load(texto)", "A08"),
        ("requests.get(url, timeout=5)", "A10"),
        ("h = hashlib.md5(clave).hexdigest()", "A02"),
        ("API_KEY = \"clave-muy-secreta-123\"", "A07"),
    ],
)
def test_patrones_peligrosos(codigo, categoria):
    senales = prefiltro.detectar_senales([Archivo(ruta="a.py", tipo="completo", contenido=codigo)])
    assert [s.owasp.split(":")[0] for s in senales] == [categoria]


@pytest.mark.parametrize(
    "codigo",
    [
        "subprocess.run([\"ls\", ruta], check=True)",
        "cur.execute(\"SELECT * FROM t WHERE id = ?\", (x,))",
        "config = yaml.load(texto, Loader=yaml.SafeLoader)",
        "requests.get(\"https://api.example.com\", timeout=5)",
        "conexion.execute_many(datos)",
    ],
)
def test_usos_seguros_no_generan_senal(codigo):
    assert prefiltro.detectar_senales([Archivo(ruta="a.py", tipo="completo", contenido=codigo)]) == []


def test_contradiccion_cuando_el_llm_no_reporta_una_senal_de_confianza_alta():
    senales = prefiltro.detectar_senales([Archivo(ruta="a.py", tipo="completo", contenido="os.system(x)")])
    advertencias = prefiltro.contradicciones(senales, [])
    assert [(a.severidad, a.linea) for a in advertencias] == [("BAJA", 1)]


def test_sin_contradiccion_si_el_llm_reporto_la_categoria():
    senales = prefiltro.detectar_senales([Archivo(ruta="a.py", tipo="completo", contenido="os.system(x)")])
    assert prefiltro.contradicciones(senales, [hallazgo("A03:2021-Injection", "a.py")]) == []


def test_las_senales_de_confianza_media_no_generan_contradiccion():
    senales = prefiltro.detectar_senales([Archivo(ruta="a.py", tipo="completo", contenido="h = hashlib.md5(x)")])
    assert prefiltro.contradicciones(senales, []) == []


# Integración en el analizador, con el LLM simulado


def solicitud_de(caso):
    return SolicitudAnalisis(tree_hash="a" * 40, archivos=[archivo_del_caso(caso)])


def test_la_manipulacion_se_reporta_aunque_el_llm_la_ignore(monkeypatch):
    # Simula un LLM engañado: no reporta nada
    monkeypatch.setattr(analizador, "consultar_modelo", lambda solicitud, senales: [])
    hallazgos = analizador.analizar(solicitud_de(CASOS[0]))
    assert any(h.owasp == prefiltro.MANIPULACION and h.severidad == "ALTA" for h in hallazgos)
    assert any(h.titulo.startswith("Patrón sensible no confirmado") for h in hallazgos)


def test_no_se_duplica_si_el_llm_ya_reporto_la_manipulacion(monkeypatch):
    del_llm = [hallazgo(prefiltro.MANIPULACION), hallazgo("A03:2021-Injection")]
    monkeypatch.setattr(analizador, "consultar_modelo", lambda solicitud, senales: list(del_llm))
    hallazgos = analizador.analizar(solicitud_de(CASOS[0]))
    assert sorted(h.owasp for h in hallazgos) == sorted(h.owasp for h in del_llm)


def test_los_caracteres_invisibles_se_conservan_aunque_el_llm_reporte_la_manipulacion(monkeypatch):
    caso = next(caso for caso in CASOS if caso["nombre"] == "ancho_cero")
    monkeypatch.setattr(analizador, "consultar_modelo", lambda solicitud, senales: [hallazgo(prefiltro.MANIPULACION)])
    titulos = [h.titulo for h in analizador.analizar(solicitud_de(caso))]
    assert prefiltro.TITULO_INVISIBLES in titulos
    assert prefiltro.TITULO_INSTRUCCIONES not in titulos


def test_las_senales_se_le_indican_al_llm_sin_copiar_codigo():
    solicitud = solicitud_de(CASOS[0])
    mensaje = analizador.armar_mensaje(solicitud, prefiltro.detectar_senales(solicitud.archivos))
    senales = mensaje.split("<senales_")[1]
    assert "archivo app.py, línea 7: ejecución de comandos con la shell" in senales
    assert "request.args" not in senales


def test_el_contenido_no_puede_inyectar_senales():
    archivo = Archivo(ruta="a.py", tipo="completo", contenido="texto = '{{SENALES}} {{MARCA}}'")
    mensaje = analizador.armar_mensaje(SolicitudAnalisis(tree_hash="a" * 40, archivos=[archivo]))
    assert "texto = '{{SENALES}} {{MARCA}}'" in mensaje
