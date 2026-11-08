"""Configuración del servidor a partir de variables de entorno."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
ANTHROPIC_EFFORT = os.environ.get("ANTHROPIC_EFFORT", "medium")

PROMPT_VERSION = os.environ.get("PROMPT_VERSION", "security_review_v2")
RUTA_PROMPT = Path(__file__).parent / "config" / "prompts" / f"{PROMPT_VERSION}.yaml"

# Severidad mínima que bloquea el commit; las menores se muestran como advertencia
SEVERIDAD_BLOQUEO = os.environ.get("SEVERIDAD_BLOQUEO", "MEDIA")

# OAuth App de GitHub; el secreto solo existe en el servidor
GITHUB_OAUTH_CLIENT_ID = os.environ.get("GITHUB_OAUTH_CLIENT_ID", "")
GITHUB_OAUTH_CLIENT_SECRET = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", "")

# Usuarios de GitHub autorizados, separados por coma. Si está vacío no se autoriza a nadie
USUARIOS_PERMITIDOS = {
    usuario.strip().lower() for usuario in os.environ.get("USUARIOS_PERMITIDOS", "").split(",") if usuario.strip()
}
