"""Flujo completo del recibo en un repositorio git temporal, incluidos los intentos de evasión."""

import subprocess

import pytest

import git_cambios
import recibo
from recibos import ReciboInvalido, verificar_commit
from server import recibos as firma
from server.autenticacion import Usuario
from server.modelos import SolicitudAnalisis


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    carpeta = tmp_path / "repo"
    carpeta.mkdir()
    monkeypatch.chdir(carpeta)
    git("init", "-q")
    git("config", "user.name", "Pruebas")
    git("config", "user.email", "pruebas@example.com")
    return carpeta


def emitir_recibo_para_staging(usuario="dev"):
    # Lo mismo que hacen el hook pre-commit y el servidor cuando el análisis se aprueba
    rutas = git("diff", "--cached", "--name-only").split()
    solicitud = SolicitudAnalisis(
        tree_hash=git_cambios.tree_hash(),
        tree_base=git_cambios.metadatos()["tree_base"],
        archivos=[git_cambios.cambio_de_archivo(ruta) for ruta in rutas],
    )
    token = firma.emitir(solicitud, Usuario(login=usuario, id=1), "id-analisis", 0, "modelo", "prompt")
    git_cambios.ruta_recibo_pendiente().write_text(token, encoding="utf-8")
    return token


def commit_con_recibo(repo, archivo, contenido, mensaje="cambio"):
    (repo / archivo).write_text(contenido)
    git("add", archivo)
    emitir_recibo_para_staging()
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text(mensaje + "\n")
    assert recibo.agregar_recibo(str(ruta_mensaje)) == 0
    git("commit", "-q", "--no-verify", "-F", str(ruta_mensaje))
    return git("rev-parse", "HEAD")


def test_commit_con_recibo_valido(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    segundo = commit_con_recibo(repo, "b.py", "y = 2\n")
    datos = verificar_commit(segundo, llave_publica)
    assert datos["sub"] == "dev"
    assert "AppSec-Receipt: " in git("log", "-1", "--format=%B")


def test_commit_con_no_verify_no_tiene_recibo(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    (repo / "b.py").write_text("y = 2\n")
    git("add", "b.py")
    git("commit", "-q", "--no-verify", "-m", "sin analisis")
    with pytest.raises(ReciboInvalido, match="no tiene recibo"):
        verificar_commit("HEAD", llave_publica)


def test_recibo_copiado_a_otro_contenido(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    token = git("log", "-1", "--format=%(trailers:key=AppSec-Receipt,valueonly)")
    (repo / "b.py").write_text("y = 2\n")
    git("add", "b.py")
    git("commit", "-q", "--no-verify", "-m", f"copiado\n\nAppSec-Receipt: {token}")
    with pytest.raises(ReciboInvalido, match="contenido"):
        verificar_commit("HEAD", llave_publica)


def test_recibo_alterado(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    token = git("log", "-1", "--format=%(trailers:key=AppSec-Receipt,valueonly)")
    alterado = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    git("commit", "-q", "--amend", "--no-verify", "-m", f"alterado\n\nAppSec-Receipt: {alterado}")
    with pytest.raises(ReciboInvalido):
        verificar_commit("HEAD", llave_publica)


def test_lavado_con_amend(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    # 1. Código sin analizar con --no-verify
    (repo / "b.py").write_text("import os\nos.system(input())\n")
    git("add", "b.py")
    git("commit", "-q", "--no-verify", "-m", "sin analisis")
    # 2. --amend sin cambios: el hook vería un diff vacío contra el commit sin analizar
    emitir_recibo_para_staging()
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text("lavado\n")
    recibo.agregar_recibo(str(ruta_mensaje))
    git("commit", "-q", "--amend", "--no-verify", "-F", str(ruta_mensaje))
    with pytest.raises(ReciboInvalido, match="padre"):
        verificar_commit("HEAD", llave_publica)


def test_recibo_de_otro_usuario(repo, llave_publica):
    commit_con_recibo(repo, "a.py", "x = 1\n")
    with pytest.raises(ReciboInvalido, match="pertenece"):
        verificar_commit("HEAD", llave_publica, usuario_esperado="otro")


def test_un_recibo_escrito_a_mano_se_reemplaza(repo, llave_publica):
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
    # --amend con un cambio: el hook calcula el análisis contra el commit que se reemplaza
    (repo / "c.py").write_text("z = 3\n")
    git("add", "c.py")
    emitir_recibo_para_staging()
    ruta_mensaje = repo.parent / "mensaje.txt"
    ruta_mensaje.write_text("amend\n")
    recibo.agregar_recibo(str(ruta_mensaje))
    git("commit", "-q", "--amend", "--no-verify", "-F", str(ruta_mensaje))
    assert "--amend" in recibo.problema_del_ultimo_commit()
    assert recibo.revisar_ultimo_commit() == 1
