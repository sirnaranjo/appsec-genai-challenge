"""Flujo completo del recibo en un repositorio git temporal, incluidos los intentos de evasión."""

import re
import subprocess
from pathlib import Path

import pytest
from identify.identify import tags_from_filename

import git_cambios
import recibo
from recibos import ReciboInvalido, diff_de_archivo, filtros_del_hook, verificar_commit
from server import recibos as firma
from server.autenticacion import Usuario
from server.modelos import SolicitudAnalisis

FILTROS = ({"python"}, re.compile("^examples/"))


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    carpeta = tmp_path / "repo"
    carpeta.mkdir()
    monkeypatch.chdir(carpeta)
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Pruebas")
    git("config", "user.email", "pruebas@example.com")
    return carpeta


def rutas_que_analiza_el_hook():
    # Lo que pre-commit le pasa al hook: archivos en staging que pasan los filtros
    tipos, exclusion = FILTROS
    rutas = git("diff", "--cached", "--name-only", "--diff-filter=d").split()
    return [ruta for ruta in rutas if tipos & tags_from_filename(ruta) and not exclusion.search(ruta)]


def emitir_recibo_para_staging(usuario="dev", rutas=None, contenido_falso=None):
    # Lo mismo que hacen el hook pre-commit y el servidor cuando el análisis se aprueba
    archivos = [git_cambios.cambio_de_archivo(ruta) for ruta in (rutas if rutas is not None else rutas_que_analiza_el_hook())]
    if contenido_falso:
        archivos[0]["contenido"] = contenido_falso
    solicitud = SolicitudAnalisis(
        tree_hash=git_cambios.tree_hash(), tree_base=git_cambios.metadatos()["tree_base"], archivos=archivos
    )
    token = firma.emitir(solicitud, Usuario(login=usuario, id=1), "id-analisis", 0, "modelo", "prompt")
    git_cambios.ruta_recibo_pendiente().write_text(token, encoding="utf-8")
    return token


def confirmar(repo, mensaje="cambio", **opciones):
    emitir_recibo_para_staging(**opciones)
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text(mensaje + "\n")
    assert recibo.agregar_recibo(str(ruta_mensaje)) == 0
    git("commit", "-q", "--no-verify", "-F", str(ruta_mensaje))
    return git("rev-parse", "HEAD")


def commit_con_recibo(repo, archivo, contenido, mensaje="cambio", **opciones):
    ruta = repo / archivo
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(contenido)
    git("add", archivo)
    return confirmar(repo, mensaje, **opciones)


def verificar(revision, llave, **opciones):
    return verificar_commit(revision, llave, FILTROS, **opciones)


# Flujo normal


def test_commit_con_recibo_valido(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    segundo = commit_con_recibo(repo, "b.py", "y = 2\n")
    datos = verificar(segundo, llave_publica)
    assert datos["sub"] == "dev"
    assert datos["rutas"] == ["b.py"]
    assert "AppSec-Receipt: " in git("log", "-1", "--format=%B")


def test_el_diff_del_hook_y_el_del_verificador_son_identicos(repo):
    (repo / "a.py").write_text("def f():\n    return 1\n")
    git("add", "a.py")
    del_hook = git_cambios.diff_staged("a.py")
    git("commit", "-q", "--no-verify", "-m", "uno")
    assert del_hook == diff_de_archivo("4b825dc642cb6eb9a060e54bf8d69288fbee4904", "HEAD", "a.py")

    (repo / "a.py").write_text("def f():\n    return 2\n")
    git("add", "a.py")
    del_hook = git_cambios.diff_staged("a.py")
    git("commit", "-q", "--no-verify", "-m", "dos")
    assert del_hook == diff_de_archivo("HEAD~1", "HEAD", "a.py")


def test_cambios_sin_codigo_no_requieren_analisis(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    commit_con_recibo(repo, "README.md", "hola\n")
    assert verificar("HEAD", llave_publica)["rutas"] == []


def test_rutas_excluidas_no_requieren_analisis(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    commit_con_recibo(repo, "examples/vulnerable.py", "import os\n")
    assert verificar("HEAD", llave_publica)["rutas"] == []


def test_lee_los_filtros_de_la_configuracion_del_proyecto():
    tipos, exclusion = filtros_del_hook(Path(__file__).resolve().parent.parent / ".pre-commit-config.yaml")
    assert "python" in tipos
    assert exclusion.search("examples/vulnerable_app.py")


# Evasiones


def test_commit_con_no_verify_no_tiene_recibo(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    (repo / "b.py").write_text("y = 2\n")
    git("add", "b.py")
    git("commit", "-q", "--no-verify", "-m", "sin analisis")
    with pytest.raises(ReciboInvalido, match="no tiene recibo"):
        verificar("HEAD", llave_publica)


def test_recibo_copiado_a_otro_contenido(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    token = git("log", "-1", "--format=%(trailers:key=AppSec-Receipt,valueonly)")
    (repo / "b.py").write_text("y = 2\n")
    git("add", "b.py")
    git("commit", "-q", "--no-verify", "-m", f"copiado\n\nAppSec-Receipt: {token}")
    with pytest.raises(ReciboInvalido, match="contenido"):
        verificar("HEAD", llave_publica)


def test_recibo_alterado(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    token = git("log", "-1", "--format=%(trailers:key=AppSec-Receipt,valueonly)")
    alterado = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    git("commit", "-q", "--amend", "--no-verify", "-m", f"alterado\n\nAppSec-Receipt: {alterado}")
    with pytest.raises(ReciboInvalido):
        verificar("HEAD", llave_publica)


def test_lavado_con_amend(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    (repo / "b.py").write_text("import os\nos.system(input())\n")
    git("add", "b.py")
    git("commit", "-q", "--no-verify", "-m", "sin analisis")
    # --amend sin cambios: el hook vería un diff vacío contra el commit sin analizar
    emitir_recibo_para_staging()
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text("lavado\n")
    recibo.agregar_recibo(str(ruta_mensaje))
    git("commit", "-q", "--amend", "--no-verify", "-F", str(ruta_mensaje))
    with pytest.raises(ReciboInvalido, match="padre"):
        verificar("HEAD", llave_publica)


def test_cliente_que_envia_diffs_falsos(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    # El tree es el real (con el código peligroso), pero al LLM se le muestra algo inofensivo
    commit_con_recibo(repo, "b.py", "import os\nos.system(input())\n", contenido_falso="+def sumar(a, b):\n+    return a + b\n")
    with pytest.raises(ReciboInvalido, match="no coincide con los cambios"):
        verificar("HEAD", llave_publica)


def test_cliente_que_omite_un_archivo_de_codigo(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    (repo / "b.py").write_text("y = 2\n")
    (repo / "c.py").write_text("import os\nos.system(input())\n")
    git("add", "b.py", "c.py")
    confirmar(repo, rutas=["b.py"])
    with pytest.raises(ReciboInvalido, match="no se analizaron: c.py"):
        verificar("HEAD", llave_publica)


def test_recibo_sin_lista_de_rutas(repo, llave_publica, monkeypatch):
    real = firma.firmar
    monkeypatch.setattr(firma, "firmar", lambda datos: real({k: v for k, v in datos.items() if k != "rutas"}))
    commit_con_recibo(repo, "a.py", "x = 1\n")
    with pytest.raises(ReciboInvalido, match="qué archivos"):
        verificar("HEAD", llave_publica)


def test_recibo_de_otro_usuario(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    with pytest.raises(ReciboInvalido, match="pertenece"):
        verificar("HEAD", llave_publica, usuario_esperado="otro")


# Merges


def preparar_ramas(repo):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    git("checkout", "-q", "-b", "rama")
    commit_con_recibo(repo, "b.py", "y = 2\n")
    git("checkout", "-q", "main")
    commit_con_recibo(repo, "c.py", "z = 3\n")


def test_merge_automatico_sin_recibo_se_acepta(repo, llave_publica):
    # Equivale al botón Merge de GitHub: combina los padres sin agregar contenido propio
    preparar_ramas(repo)
    git("merge", "-q", "--no-ff", "--no-verify", "-m", "Merge rama", "rama")
    assert verificar("HEAD", llave_publica)["sub"] == "(merge)"


def test_merge_con_contenido_propio_sin_recibo_se_rechaza(repo, llave_publica):
    preparar_ramas(repo)
    git("merge", "-q", "--no-ff", "--no-commit", "rama")
    (repo / "d.py").write_text("import os\nos.system(input())\n")
    git("add", "d.py")
    git("commit", "-q", "--no-verify", "-m", "Merge con agregado")
    with pytest.raises(ReciboInvalido, match="no tiene recibo"):
        verificar("HEAD", llave_publica)


def test_merge_local_con_recibo_se_verifica(repo, llave_publica):
    preparar_ramas(repo)
    git("merge", "-q", "--no-ff", "--no-commit", "rama")
    confirmar(repo, "Merge rama")
    assert verificar("HEAD", llave_publica)["rutas"] == ["b.py"]


# Hooks locales


def test_un_recibo_escrito_a_mano_se_reemplaza(repo):
    (repo / "a.py").write_text("x = 1\n")
    git("add", "a.py")
    real = emitir_recibo_para_staging()
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text("cambio\n\nAppSec-Receipt: inventado\n")
    recibo.agregar_recibo(str(ruta_mensaje))
    mensaje = ruta_mensaje.read_text()
    assert "inventado" not in mensaje
    assert real in mensaje


def test_sin_recibo_pendiente_se_rechaza_el_commit(repo):
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text("cambio\n")
    assert recibo.agregar_recibo(str(ruta_mensaje)) == 1


def test_cambios_despues_del_analisis_se_rechazan(repo):
    (repo / "a.py").write_text("x = 1\n")
    git("add", "a.py")
    emitir_recibo_para_staging()
    (repo / "b.py").write_text("y = 2\n")
    git("add", "b.py")
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text("cambio\n")
    assert recibo.agregar_recibo(str(ruta_mensaje)) == 1


def test_revision_local_de_un_commit_valido(repo):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    commit_con_recibo(repo, "b.py", "y = 2\n")
    assert recibo.revisar_ultimo_commit() == 0


def test_revision_local_avisa_del_no_verify(repo):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    (repo / "b.py").write_text("y = 2\n")
    git("add", "b.py")
    git("commit", "-q", "--no-verify", "-m", "sin analisis")
    assert "no tiene recibo" in recibo.problema_del_ultimo_commit()


def test_revision_local_avisa_del_amend(repo):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    commit_con_recibo(repo, "b.py", "y = 2\n")
    (repo / "c.py").write_text("z = 3\n")
    git("add", "c.py")
    emitir_recibo_para_staging()
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text("amend\n")
    recibo.agregar_recibo(str(ruta_mensaje))
    git("commit", "-q", "--amend", "--no-verify", "-F", str(ruta_mensaje))
    assert "--amend" in recibo.problema_del_ultimo_commit()
    assert recibo.revisar_ultimo_commit() == 1
