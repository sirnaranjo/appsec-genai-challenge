"""Salida del hook en la terminal."""

import presentacion

RESULTADO = {
    "id_analisis": "1234",
    "aprobado": False,
    "modelo": "modelo",
    "version_prompt": "v",
    "severidad_bloqueo": "MEDIA",
    "hallazgos": [
        {
            "owasp": "A03:2021-Injection",
            "titulo": "Titulo [bold]literal[/bold]",
            "archivo": "app.py",
            "linea": 4,
            "severidad": "ALTA",
            "riesgo": "Riesgo",
            "solucion": "Solución",
            "codigo_sugerido": "x = 1  # \x1b]0;titulo\x07\x1b[2J",
        }
    ],
}


def test_limpiar_elimina_caracteres_de_control():
    assert presentacion.limpiar("a\x1b[2Jb\x07c\x9bd") == "a[2Jbcd"


def test_limpiar_conserva_saltos_de_linea_y_tabulaciones():
    assert presentacion.limpiar("a\nb\tc") == "a\nb\tc"


def test_limpiar_no_modifica_valores_que_no_son_texto():
    assert presentacion.limpiar(None) is None
    assert presentacion.limpiar(4) == 4


def test_la_salida_no_contiene_secuencias_del_contenido(capsys):
    presentacion.mostrar_resultado(RESULTADO)
    salida = capsys.readouterr().out
    assert "\x1b]0;" not in salida
    assert "\x1b[2J" not in salida


def test_el_texto_del_llm_no_se_interpreta_como_formato(capsys):
    presentacion.mostrar_resultado(RESULTADO)
    assert "[bold]literal[/bold]" in capsys.readouterr().out


def test_hallazgos_bajo_el_umbral_son_advertencias():
    assert not presentacion.bloquea({"severidad": "BAJA"}, "MEDIA")
    assert presentacion.bloquea({"severidad": "MEDIA"}, "MEDIA")
    assert presentacion.bloquea({"severidad": "CRITICA"}, "ALTA")
