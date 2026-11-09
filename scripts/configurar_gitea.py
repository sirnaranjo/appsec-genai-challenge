"""Configura la instancia de Gitea de docker compose como servidor Git con control de integridad.

Pasos (se pueden repetir sin efectos duplicados):
1. Usuario administrador, con la contraseña que se indique (o una aleatoria) guardada en el almacén de credenciales.
2. Login con GitHub (OAuth 2.0) usando GITHUB_OAUTH_CLIENT_ID y GITHUB_OAUTH_CLIENT_SECRET del .env.
3. Organización, equipo de desarrolladores y repositorio.
4. Contenido inicial: la rama actual de este repositorio se sube antes de activar el hook.
5. Hook pre-receive con verifier/pre_receive.py, exigiendo que el recibo sea de quien hace el push.
6. Solo merge commits y rama principal protegida, incluidos los archivos que definen el control.
7. Opcional: réplica automática a GitHub (GITHUB_ESPEJO_URL y GITHUB_ESPEJO_TOKEN en el .env).

Uso:
    python scripts/configurar_gitea.py                    configuración inicial
    python scripts/configurar_gitea.py --autorizar LOGIN  da permiso de escritura a quien ya inició sesión con GitHub
    python scripts/configurar_gitea.py --clave-administrador  muestra la contraseña para entrar a la web como administrador
"""

import argparse
import base64
import getpass
import os
import secrets
import subprocess
import sys
from pathlib import Path

import httpx
import keyring
from dotenv import load_dotenv
from keyring.errors import KeyringError

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")

GITEA = os.environ.get("GITEA_URL", "http://localhost:3000")
API = f"{GITEA}/api/v1"
CONTENEDOR = "appsec-gitea"
ADMINISTRADOR = "administrador"
ORGANIZACION = "appsec"
EQUIPO = "desarrolladores"
REPOSITORIO = "proyecto"
SERVICIO_KEYRING = "appsec-genai-gitea-administrador"
ALMACEN = "almacén de credenciales del sistema"
# Solo si el sistema no tiene almacén de credenciales, como un servidor Linux sin escritorio
ARCHIVO_CLAVE = RAIZ / "data" / "gitea-administrador.txt"
CLAVE_MINIMA = 12
# Definen qué se analiza y cómo se verifica: en main no se cambian con un push ni con el merge de un desarrollador.
# Por ejemplo, agregar una ruta al exclude y luego subir código vulnerable en ella
ARCHIVOS_PROTEGIDOS = [".pre-commit-config.yaml", ".gitattributes", "verifier/**", "hooks/**", ".github/**"]


def docker(*args, entrada=None):
    # El contenido se envía como bytes: con texto, Windows convertiría los saltos de línea a CRLF
    return subprocess.run(["docker", "exec", "-i", "-u", "git", CONTENEDOR, *args], input=entrada, capture_output=True)


def git(*args, carpeta=RAIZ, credenciales=None):
    # Sin el administrador de credenciales del sistema: se usan las que se indiquen
    entorno = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if credenciales:
        # Por variables de entorno y no en la URL: así no aparecen en la lista de procesos ni en los errores
        basico = base64.b64encode(":".join(credenciales).encode()).decode()
        entorno.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basico}"})
    return subprocess.run(["git", "-c", "credential.helper=", *args], cwd=carpeta, capture_output=True, text=True, env=entorno)


def crear_usuario_local(nombre, clave, administrador=False):
    # Solo para el administrador y las pruebas; los desarrolladores entran con GitHub
    resultado = docker("gitea", "admin", "user", "create", "--username", nombre, "--password", clave,
                       "--email", f"{nombre}@appsec.local", "--must-change-password=false",
                       *(["--admin"] if administrador else []))
    if resultado.returncode == 0:
        return
    if b"already exists" not in resultado.stderr:
        raise RuntimeError(resultado.stderr.decode(errors="replace"))
    # Ya existía: recibe la contraseña nueva, por ejemplo si se perdió la guardada
    cambio = docker("gitea", "admin", "user", "change-password", "--username", nombre, "--password", clave,
                    "--must-change-password=false")
    if cambio.returncode != 0:
        raise RuntimeError(cambio.stderr.decode(errors="replace"))


def guardar_clave(clave):
    try:
        keyring.set_password(SERVICIO_KEYRING, GITEA, clave)
        return ALMACEN
    except KeyringError:
        ARCHIVO_CLAVE.parent.mkdir(exist_ok=True)
        # Solo el dueño puede leerlo
        ARCHIVO_CLAVE.touch(mode=0o600)
        ARCHIVO_CLAVE.write_text(clave, encoding="utf-8")
        return str(ARCHIVO_CLAVE.relative_to(RAIZ))


def leer_clave():
    try:
        clave = keyring.get_password(SERVICIO_KEYRING, GITEA)
    except KeyringError:
        clave = None
    if clave is None and ARCHIVO_CLAVE.exists():
        clave = ARCHIVO_CLAVE.read_text(encoding="utf-8").strip()
        # La clave que una versión anterior guardó en el archivo pasa al almacén del sistema, si está disponible
        if guardar_clave(clave) == ALMACEN:
            ARCHIVO_CLAVE.unlink()
    return clave


def ubicacion_clave():
    return ARCHIVO_CLAVE.relative_to(RAIZ).as_posix() if ARCHIVO_CLAVE.exists() else f"el {ALMACEN}"


def hay_terminal():
    return sys.stdin.isatty()


def pedir_clave():
    # Sin terminal interactiva, como en las pruebas automáticas, se genera una aleatoria sin preguntar
    if not hay_terminal():
        return secrets.token_urlsafe(24)
    while True:
        clave = getpass.getpass("Contraseña para el administrador de Gitea (Enter para generar una aleatoria): ")
        if not clave:
            return secrets.token_urlsafe(24)
        if len(clave) < CLAVE_MINIMA:
            print(f"Debe tener al menos {CLAVE_MINIMA} caracteres.")
        elif getpass.getpass("Repítela: ") != clave:
            print("Las contraseñas no coinciden.")
        else:
            return clave


def credenciales_administrador():
    clave = leer_clave()
    if clave is None:
        clave = pedir_clave()
        crear_usuario_local(ADMINISTRADOR, clave, administrador=True)
        guardar_clave(clave)
    return ADMINISTRADOR, clave


def configurar_login_github():
    client_id = os.environ.get("GITHUB_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        return "omitido: faltan GITHUB_OAUTH_CLIENT_ID y GITHUB_OAUTH_CLIENT_SECRET en el .env"
    if b"github" in docker("gitea", "admin", "auth", "list").stdout:
        return "ya estaba configurado"
    resultado = docker("gitea", "admin", "auth", "add-oauth", "--name", "github", "--provider", "github",
                       "--key", client_id, "--secret", client_secret)
    if resultado.returncode != 0:
        raise RuntimeError(resultado.stderr.decode(errors="replace"))
    return "configurado"


def crear_si_no_existe(cliente, ruta, datos):
    respuesta = cliente.post(ruta, json=datos)
    if respuesta.status_code not in (201, 409, 422):
        respuesta.raise_for_status()
    return respuesta


def id_equipo(cliente):
    equipos = cliente.get(f"/orgs/{ORGANIZACION}/teams").json()
    return next(equipo["id"] for equipo in equipos if equipo["name"] == EQUIPO)


def crear_repositorio(cliente, nombre=REPOSITORIO):
    crear_si_no_existe(cliente, "/orgs", {"username": ORGANIZACION, "visibility": "public"})
    crear_si_no_existe(cliente, f"/orgs/{ORGANIZACION}/teams", {
        "name": EQUIPO, "permission": "write", "includes_all_repositories": True,
        "units": ["repo.code", "repo.pulls", "repo.issues"],
    })
    crear_si_no_existe(cliente, f"/orgs/{ORGANIZACION}/repos", {"name": nombre, "default_branch": "main"})
    # Solo merge commits: squash y rebase crean commits nuevos sin recibo, que el hook rechazaría
    cliente.patch(f"/repos/{ORGANIZACION}/{nombre}", json={
        "allow_merge_commits": True, "allow_squash_merge": False, "allow_rebase": False,
        "allow_rebase_explicit": False, "allow_fast_forward_only_merge": False, "default_merge_style": "merge",
    }).raise_for_status()


def proteger_main(cliente, nombre=REPOSITORIO):
    # Después del contenido inicial: Gitea no puede revisar los archivos protegidos en el primer push de una rama.
    # Sin force push ni borrado, y solo un administrador puede integrar un pull request que modifique esos archivos
    proteccion = {"enable_push": True, "protected_file_patterns": ";".join(ARCHIVOS_PROTEGIDOS)}
    ruta = f"/repos/{ORGANIZACION}/{nombre}/branch_protections"
    if any(existente["rule_name"] == "main" for existente in cliente.get(ruta).json()):
        cliente.patch(f"{ruta}/main", json=proteccion).raise_for_status()
    else:
        cliente.post(ruta, json={"rule_name": "main", **proteccion}).raise_for_status()


def subir_contenido_inicial(cliente, usuario, clave, nombre=REPOSITORIO, carpeta=RAIZ):
    # El historial existente se sube antes de activar el hook: sus commits no tienen recibos
    if not cliente.get(f"/repos/{ORGANIZACION}/{nombre}").json()["empty"]:
        return "el repositorio ya tenía contenido"
    destino = f"{GITEA}/{ORGANIZACION}/{nombre}.git"
    resultado = git("push", destino, "HEAD:refs/heads/main", carpeta=carpeta, credenciales=(usuario, clave))
    if resultado.returncode != 0:
        raise RuntimeError(resultado.stderr)
    return "subido"


def instalar_hook(nombre=REPOSITORIO):
    carpeta = f"/data/git/repositories/{ORGANIZACION}/{nombre}.git/hooks/pre-receive.d"
    hook = (
        "#!/bin/sh\n"
        "exec python3 /appsec/verifier/pre_receive.py --llave /appsec/receipt_public.pem --usuario-desde GITEA_PUSHER_NAME\n"
    )
    resultado = docker("sh", "-c", f"mkdir -p {carpeta} && cat > {carpeta}/appsec && chmod +x {carpeta}/appsec",
                       entrada=hook.encode())
    if resultado.returncode != 0:
        raise RuntimeError(resultado.stderr.decode(errors="replace"))


def configurar_espejo(cliente):
    url = os.environ.get("GITHUB_ESPEJO_URL")
    token = os.environ.get("GITHUB_ESPEJO_TOKEN")
    if not url or not token:
        return "omitido: sin GITHUB_ESPEJO_URL y GITHUB_ESPEJO_TOKEN en el .env"
    existentes = cliente.get(f"/repos/{ORGANIZACION}/{REPOSITORIO}/push_mirrors").json()
    if any(espejo["remote_address"] == url for espejo in existentes):
        return "ya estaba configurado"
    cliente.post(f"/repos/{ORGANIZACION}/{REPOSITORIO}/push_mirrors", json={
        "remote_address": url, "remote_username": "oauth2", "remote_password": token,
        "interval": "8h0m0s", "sync_on_commit": True,
    }).raise_for_status()
    return "configurado"


def autorizar(cliente, login):
    respuesta = cliente.put(f"/teams/{id_equipo(cliente)}/members/{login}")
    if respuesta.status_code == 404:
        return f"{login} no existe en Gitea: primero debe iniciar sesión con GitHub en {GITEA}"
    respuesta.raise_for_status()
    return f"{login} tiene permiso de escritura en {ORGANIZACION}/{REPOSITORIO}"


def main():
    parser = argparse.ArgumentParser(description="Configuración de Gitea para el control de integridad")
    parser.add_argument("--autorizar", metavar="LOGIN", help="usuario de GitHub que ya inició sesión en Gitea")
    parser.add_argument("--clave-administrador", action="store_true",
                        help="muestra la contraseña del administrador para entrar a la web de Gitea")
    argumentos = parser.parse_args()

    usuario, clave = credenciales_administrador()
    if argumentos.clave_administrador:
        print(clave)
        return 0
    with httpx.Client(base_url=API, auth=(usuario, clave), timeout=30) as cliente:
        if argumentos.autorizar:
            print(autorizar(cliente, argumentos.autorizar))
            return 0

        print(f"Administrador:          {usuario} (contraseña en {ubicacion_clave()}; se muestra con --clave-administrador)")
        print(f"Login con GitHub:       {configurar_login_github()}")
        crear_repositorio(cliente)
        print(f"Repositorio:            {GITEA}/{ORGANIZACION}/{REPOSITORIO}")
        print(f"Contenido inicial:      {subir_contenido_inicial(cliente, usuario, clave)}")
        instalar_hook()
        print("Hook pre-receive:       instalado")
        proteger_main(cliente)
        print(f"Archivos protegidos:    {', '.join(ARCHIVOS_PROTEGIDOS)}")
        print(f"Réplica a GitHub:       {configurar_espejo(cliente)}")
    print()
    print("Siguientes pasos para cada desarrollador:")
    print(f"  1. Iniciar sesión en {GITEA} con 'Iniciar sesión con GitHub'")
    print("  2. python scripts/configurar_gitea.py --autorizar <usuario de GitHub>")
    print("  3. Crear un token de acceso en Gitea (Configuración > Aplicaciones) y agregar el remoto:")
    print(f"     git remote add gitea {GITEA}/{ORGANIZACION}/{REPOSITORIO}.git")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
