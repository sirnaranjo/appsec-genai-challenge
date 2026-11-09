"""Demostración del hook con los ejemplos de examples/ en un repositorio temporal.

Requiere el servidor de análisis en ejecución. Uso:
    python scripts/demo.py [nombre_del_ejemplo ...]
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
EJEMPLOS = ["secure_app.py", "vulnerable_app.py", "prompt_injection_app.py"]


def git(repo, *args, salida=False):
    return subprocess.run(["git", *args], cwd=repo, check=not salida, capture_output=not salida)


def preparar_repositorio(repo):
    # Repositorio nuevo con los hooks y la configuración de este proyecto. El primer commit se hace
    # con --no-verify porque solo prepara la demostración
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Demo")
    git(repo, "config", "user.email", "demo@example.com")
    shutil.copytree(RAIZ / "hooks", repo / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(RAIZ / ".pre-commit-config.yaml", repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "Repositorio de demostracion")
    subprocess.run([sys.executable, "-m", "pre_commit", "install"], cwd=repo, check=True, capture_output=True)


def intentar_commit(repo, ejemplo):
    # El ejemplo se copia en la raíz porque examples/ está excluido en la configuración del hook
    shutil.copy(RAIZ / "examples" / ejemplo, repo / ejemplo)
    git(repo, "add", ejemplo)

    print(f"\n{'=' * 100}\n  git commit con {ejemplo}\n{'=' * 100}", flush=True)
    aprobado = git(repo, "commit", "-m", f"Agrega {ejemplo}", salida=True).returncode == 0
    print(f"\nResultado: {'COMMIT APROBADO' if aprobado else 'COMMIT RECHAZADO'}", flush=True)

    # Si se rechazó, se deja el repositorio limpio para el siguiente ejemplo
    if not aprobado:
        git(repo, "rm", "-q", "--cached", ejemplo)
        (repo / ejemplo).unlink()
    return aprobado


def main(ejemplos):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directorio:
        repo = Path(directorio)
        preparar_repositorio(repo)
        resultados = {ejemplo: intentar_commit(repo, ejemplo) for ejemplo in ejemplos}

    print(f"\n{'=' * 100}\n  Resumen\n{'=' * 100}")
    for ejemplo, aprobado in resultados.items():
        print(f"  {ejemplo:<28} {'aprobado' if aprobado else 'rechazado'}")


if __name__ == "__main__":
    main(sys.argv[1:] or EJEMPLOS)
