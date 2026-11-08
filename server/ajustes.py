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
