"""Recolección de cambios desde git en un repositorio temporal."""

import subprocess

import pytest

import git_cambios


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    git("init", "-q")
    git("config", "user.name", "Pruebas")
    git("config", "user.email", "pruebas@example.com")
    return tmp_path


def test_archivo_nuevo_se_envia_como_diff(repo):
    (repo / "app.py").write_text("x = 1\n")
    git("add", "app.py")
    cambio = git_cambios.cambio_de_archivo("app.py")
    assert cambio["tipo"] == "diff"
    assert "+x = 1" in cambio["contenido"]


def test_tree_hash_coincide_con_el_commit(repo):
    (repo / "app.py").write_text("x = 1\n")
    git("add", "app.py")
    tree_hash = git_cambios.tree_hash()
    git("commit", "-q", "--no-verify", "-m", "prueba")
    assert git("rev-parse", "HEAD^{tree}") == tree_hash


def test_se_analiza_la_version_en_staging(repo):
    (repo / "app.py").write_text("x = 1\n")
    git("add", "app.py")
    (repo / "app.py").write_text("x = 2\n")
    contenido = git_cambios.cambio_de_archivo("app.py")["contenido"]
    assert "x = 1" in contenido
    assert "x = 2" not in contenido


def test_archivo_sin_cambios_se_envia_completo(repo):
    (repo / "app.py").write_text("x = 1\n")
    git("add", "app.py")
    git("commit", "-q", "--no-verify", "-m", "prueba")
    cambio = git_cambios.cambio_de_archivo("app.py")
    assert cambio["tipo"] == "completo"
    assert cambio["contenido"] == "x = 1\n"
