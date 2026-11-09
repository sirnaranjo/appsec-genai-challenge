"""Gitea con el hook pre-receive: el push se rechaza en el servidor. Requiere docker compose y RUN_GITEA_TESTS=1."""

import base64
import os
import secrets
import subprocess
from pathlib import Path

import httpx
import pytest

import configurar_gitea as gitea
import git_cambios
import recibo
from server import ajustes, recibos
from server.autenticacion import Usuario
from server.modelos import SolicitudAnalisis

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_GITEA_TESTS") != "1", reason="Requiere Gitea en docker compose; activar con RUN_GITEA_TESTS=1"
)

RAIZ = Path(__file__).resolve().parent.parent
NOMBRE = f"pruebas-{secrets.token_hex(3)}"


@pytest.fixture(scope="module")
def entorno():
    administrador, clave_administrador = gitea.credenciales_administrador()
    cliente = httpx.Client(base_url=gitea.API, auth=(administrador, clave_administrador), timeout=60)
    gitea.crear_repositorio(cliente, NOMBRE)
    gitea.subir_contenido_inicial(cliente, administrador, clave_administrador, NOMBRE)
    gitea.instalar_hook(NOMBRE)

    usuarios = {}
    for rol in ("autor", "revisor"):
        nombre, clave = f"{rol}-{secrets.token_hex(3)}", secrets.token_urlsafe(18)
        gitea.crear_usuario_local(nombre, clave)
        gitea.autorizar(cliente, nombre)
        usuarios[rol] = (nombre, clave)
    yield cliente, usuarios
    cliente.delete(f"/repos/{gitea.ORGANIZACION}/{NOMBRE}")
    for nombre, _ in usuarios.values():
        cliente.delete(f"/admin/users/{nombre}", params={"purge": "true"})
    cliente.close()


@pytest.fixture
def trabajo(entorno, tmp_path, monkeypatch):
    # Los recibos se firman con la llave real: es la que el hook de Gitea usa para verificar
    monkeypatch.setattr(ajustes, "RUTA_LLAVE_PRIVADA", RAIZ / "keys" / "receipt_private.pem")
    recibos.llave_privada.cache_clear()
    _, usuarios = entorno
    carpeta = tmp_path / "trabajo"
    assert git("clone", "-q", url(*usuarios["autor"]), str(carpeta)).returncode == 0
    monkeypatch.chdir(carpeta)
    git("config", "user.name", "Pruebas")
    git("config", "user.email", "pruebas@example.com")
    yield usuarios
    recibos.llave_privada.cache_clear()


def git(*args):
    return gitea.git(*args, carpeta=Path.cwd())


def url(usuario, clave):
    return f"{gitea.GITEA.replace('://', f'://{usuario}:{clave}@')}/{gitea.ORGANIZACION}/{NOMBRE}.git"


def commit_con_recibo(archivo, contenido, login):
    Path(archivo).write_text(contenido)
    git("add", archivo)
    rutas = [r for r in git("diff", "--cached", "--name-only").stdout.split() if r.endswith(".py")]
    solicitud = SolicitudAnalisis(
        tree_hash=git_cambios.tree_hash(), tree_base=git_cambios.metadatos()["tree_base"],
        archivos=[git_cambios.cambio_de_archivo(ruta) for ruta in rutas],
    )
    token = recibos.emitir(solicitud, Usuario(login=login, id=1), "prueba", 0, "modelo", "prompt")
    git_cambios.ruta_recibo_pendiente().write_text(token, encoding="utf-8")
    mensaje = Path.cwd().parent / "mensaje.txt"
    mensaje.write_text(f"Agrega {archivo}\n")
    assert recibo.agregar_recibo(str(mensaje)) == 0
    git("commit", "-q", "--no-verify", "-F", str(mensaje))


def test_push_sin_recibo_se_rechaza(trabajo):
    Path("malo.py").write_text("import os\nos.system(input())\n")
    git("add", "malo.py")
    git("commit", "-q", "--no-verify", "-m", "Sin analisis")
    resultado = git("push", url(*trabajo["autor"]), "main")
    assert resultado.returncode != 0
    assert "no tiene recibo" in resultado.stderr


def test_push_con_recibo_propio_se_acepta(trabajo):
    autor = trabajo["autor"]
    commit_con_recibo("bueno.py", "x = 1\n", autor[0])
    resultado = git("push", url(*autor), "main")
    assert resultado.returncode == 0, resultado.stderr


def test_push_con_recibo_de_otra_persona_se_rechaza(trabajo):
    commit_con_recibo("ajeno.py", "y = 2\n", trabajo["autor"][0])
    resultado = git("push", url(*trabajo["revisor"]), "main")
    assert resultado.returncode != 0
    assert "pertenece a" in resultado.stderr


def crear_pr(entorno, trabajo, rama, archivo):
    cliente, _ = entorno
    git("checkout", "-q", "-b", rama)
    commit_con_recibo(archivo, "def f():\n    return 1\n", trabajo["autor"][0])
    assert git("push", "-q", url(*trabajo["autor"]), rama).returncode == 0
    return httpx.post(
        f"{gitea.API}/repos/{gitea.ORGANIZACION}/{NOMBRE}/pulls", auth=trabajo["autor"],
        json={"head": rama, "base": "main", "title": rama}, timeout=60,
    ).json()["number"]


def test_merge_web_hecho_por_otra_persona_se_acepta(entorno, trabajo):
    numero = crear_pr(entorno, trabajo, "rama-merge", "funcion.py")
    respuesta = httpx.post(f"{gitea.API}/repos/{gitea.ORGANIZACION}/{NOMBRE}/pulls/{numero}/merge",
                           auth=trabajo["revisor"], json={"Do": "merge"}, timeout=60)
    assert respuesta.status_code == 200, respuesta.text


def test_squash_merge_no_esta_permitido(entorno, trabajo):
    numero = crear_pr(entorno, trabajo, "rama-squash", "otra.py")
    respuesta = httpx.post(f"{gitea.API}/repos/{gitea.ORGANIZACION}/{NOMBRE}/pulls/{numero}/merge",
                           auth=trabajo["autor"], json={"Do": "squash"}, timeout=60)
    assert respuesta.status_code != 200


def test_commit_desde_la_web_se_rechaza(trabajo):
    contenido = base64.b64encode(b"import os\nos.system(input())\n").decode()
    respuesta = httpx.post(f"{gitea.API}/repos/{gitea.ORGANIZACION}/{NOMBRE}/contents/web.py", auth=trabajo["autor"],
                           json={"content": contenido, "message": "Edicion web", "branch": "main"}, timeout=60)
    assert respuesta.status_code not in (200, 201)


def test_commits_de_un_fork_sin_recibo_no_entran_por_un_pull_request(trabajo):
    autor = trabajo["autor"]
    # Los forks no tienen el hook: sus commits llegan al servidor sin verificar
    respuesta = httpx.post(f"{gitea.API}/repos/{gitea.ORGANIZACION}/{NOMBRE}/forks", auth=autor, json={}, timeout=60)
    assert respuesta.status_code == 202, respuesta.text
    Path("fork.py").write_text("import os\nos.system(input())\n")
    git("add", "fork.py")
    git("commit", "-q", "--no-verify", "-m", "Desde un fork")
    fork = f"{gitea.GITEA.replace('://', f'://{autor[0]}:{autor[1]}@')}/{autor[0]}/{NOMBRE}.git"
    assert git("push", fork, "HEAD:main").returncode == 0

    # Al abrir el PR, Gitea copia los commits del fork a refs/pull/N/head con un push interno
    # que también pasa por el hook: el PR no se puede crear y el código no entra al repositorio
    pr = httpx.post(f"{gitea.API}/repos/{gitea.ORGANIZACION}/{NOMBRE}/pulls", auth=autor,
                    json={"head": f"{autor[0]}:main", "base": "main", "title": "Desde un fork"}, timeout=60)
    assert pr.status_code != 201
    sha = git("rev-parse", "HEAD").stdout.strip()
    commit = httpx.get(f"{gitea.API}/repos/{gitea.ORGANIZACION}/{NOMBRE}/git/commits/{sha}", auth=autor, timeout=60)
    assert commit.status_code == 404
