"""Hook pre-receive en un servidor Git local: el push se rechaza antes de que el código llegue al remoto."""

import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from test_flujo_recibo import commit_con_recibo, confirmar

RAIZ = Path(__file__).resolve().parent.parent


def git(*args, carpeta=None, verificar=True):
    return subprocess.run(["git", *args], cwd=carpeta, capture_output=True, text=True, check=verificar)


@pytest.fixture
def servidor(tmp_path, monkeypatch, llave_publica):
    # Repositorio de trabajo con la configuración del proyecto, clonado como servidor "desnudo"
    trabajo = tmp_path / "repo"
    trabajo.mkdir()
    monkeypatch.chdir(trabajo)
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Pruebas")
    git("config", "user.email", "pruebas@example.com")
    (trabajo / ".pre-commit-config.yaml").write_text((RAIZ / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    git("add", ".pre-commit-config.yaml")
    git("commit", "-q", "--no-verify", "-m", "Configuracion")

    remoto = tmp_path / "servidor.git"
    git("clone", "-q", "--bare", str(trabajo), str(remoto))
    git("remote", "add", "origin", str(remoto))
    git("fetch", "-q", "origin")

    llave = tmp_path / "publica.pem"
    llave.write_bytes(
        llave_publica.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    hook = remoto / "hooks" / "pre-receive"
    hook.write_text(
        "#!/bin/sh\n"
        f'exec "{Path(sys.executable).as_posix()}" "{(RAIZ / "verifier" / "pre_receive.py").as_posix()}" '
        f'--llave "{llave.as_posix()}"\n',
        newline="\n",
    )
    hook.chmod(0o755)
    return remoto


def push(*refs):
    return git("push", "origin", *refs, verificar=False)


def rama_en_servidor(remoto, rama="main"):
    return git("rev-parse", rama, carpeta=remoto).stdout.strip()


def test_push_sin_recibo_se_rechaza(servidor):
    antes = rama_en_servidor(servidor)
    Path("malo.py").write_text("import os\nos.system(input())\n")
    git("add", "malo.py")
    git("commit", "-q", "--no-verify", "-m", "Sin analisis")
    resultado = push("main")
    assert resultado.returncode != 0
    assert "no tiene recibo" in resultado.stderr
    assert "pre-receive hook declined" in resultado.stderr
    # El código nunca llegó al servidor
    assert rama_en_servidor(servidor) == antes


def test_push_con_recibo_se_acepta(servidor):
    sha = commit_con_recibo(Path.cwd(), "bueno.py", "x = 1\n")
    resultado = push("main")
    assert resultado.returncode == 0, resultado.stderr
    assert "OK" in resultado.stderr
    assert rama_en_servidor(servidor) == sha


def test_un_commit_invalido_rechaza_todo_el_push(servidor):
    antes = rama_en_servidor(servidor)
    commit_con_recibo(Path.cwd(), "bueno.py", "x = 1\n")
    Path("malo.py").write_text("y = 2\n")
    git("add", "malo.py")
    git("commit", "-q", "--no-verify", "-m", "Sin analisis")
    assert push("main").returncode != 0
    assert rama_en_servidor(servidor) == antes


def test_rama_nueva_se_verifica(servidor):
    git("checkout", "-q", "-b", "nueva")
    Path("malo.py").write_text("y = 2\n")
    git("add", "malo.py")
    git("commit", "-q", "--no-verify", "-m", "Sin analisis")
    assert push("nueva").returncode != 0

    git("reset", "-q", "--hard", "main")
    commit_con_recibo(Path.cwd(), "bueno.py", "x = 1\n")
    assert push("nueva").returncode == 0


def test_borrar_una_rama_se_permite(servidor):
    commit_con_recibo(Path.cwd(), "bueno.py", "x = 1\n")
    assert push("main:temporal").returncode == 0
    assert push(":temporal").returncode == 0


def test_el_push_no_puede_agregar_exclusiones_propias(servidor):
    # El commit agrega malo.py al exclude y no lo envía al análisis: el servidor usa su configuración
    configuracion = Path(".pre-commit-config.yaml")
    configuracion.write_text(configuracion.read_text().replace("exclude: ^examples/", "exclude: ^(examples/|malo\\.py)"))
    Path("malo.py").write_text("import os\nos.system(input())\n")
    git("add", "malo.py", ".pre-commit-config.yaml")
    confirmar(Path.cwd(), rutas=[])
    resultado = push("main")
    assert resultado.returncode != 0
    assert "no se analizaron: malo.py" in resultado.stderr
