"""Configuración del servidor a partir de variables de entorno."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

RAIZ_PROYECTO = Path(__file__).resolve().parent.parent


def ruta_del_proyecto(valor):
    # Una ruta relativa se toma desde la raíz del proyecto, no desde la carpeta donde se inicia el servidor
    ruta = Path(valor)
    return ruta if ruta.is_absolute() else RAIZ_PROYECTO / ruta


# Modelo de Claude y nivel de esfuerzo del análisis (low, medium o high)
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
ANTHROPIC_EFFORT = os.environ.get("ANTHROPIC_EFFORT", "medium")

# Versión del prompt: nombre del archivo YAML en config/prompts
PROMPT_VERSION = os.environ.get("PROMPT_VERSION", "security_review_v3")
RUTA_PROMPT = Path(__file__).parent / "config" / "prompts" / f"{PROMPT_VERSION}.yaml"

# Severidad mínima que bloquea el commit; las menores se muestran como advertencia
SEVERIDAD_BLOQUEO = os.environ.get("SEVERIDAD_BLOQUEO", "MEDIA")

# OAuth App de GitHub; el secreto solo existe en el servidor
GITHUB_OAUTH_CLIENT_ID = os.environ.get("GITHUB_OAUTH_CLIENT_ID", "")
GITHUB_OAUTH_CLIENT_SECRET = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", "")

# Usuarios de GitHub autorizados, separados por coma. Si está vacío no se autoriza a nadie.
# Se guardan en minúsculas porque GitHub no distingue mayúsculas en los nombres de usuario
USUARIOS_PERMITIDOS = {
    usuario.strip().lower() for usuario in os.environ.get("USUARIOS_PERMITIDOS", "").split(",") if usuario.strip()
}

# Integridad: llave con la que se firman los recibos y registro de auditoría de los análisis
RUTA_LLAVE_PRIVADA = ruta_del_proyecto(os.environ.get("RECEIPT_PRIVATE_KEY_PATH", "keys/receipt_private.pem"))
RUTA_BASE_DATOS = ruta_del_proyecto(os.environ.get("DATABASE_PATH", "data/appsec.db"))
# Campo iss de los recibos: identifica al servidor que los emite
EMISOR_RECIBOS = "appsec-genai"
