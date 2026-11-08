"""API del servidor de análisis."""

import logging
import uuid

from fastapi import FastAPI, HTTPException

from server import ajustes
from server.analizador import VERSION_PROMPT, ErrorAnalisis, analizar
from server.modelos import ResultadoAnalisis, SolicitudAnalisis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("appsec")

app = FastAPI(title="AppSec GenAI", version="0.2.0")

SEVERIDADES = ["BAJA", "MEDIA", "ALTA", "CRITICA"]


def bloquea_commit(hallazgo):
    return SEVERIDADES.index(hallazgo.severidad) >= SEVERIDADES.index(ajustes.SEVERIDAD_BLOQUEO)


@app.get("/health")
def health():
    return {"estado": "ok"}


@app.post("/analyze", response_model=ResultadoAnalisis)
def analyze(solicitud: SolicitudAnalisis):
    id_analisis = str(uuid.uuid4())
    try:
        hallazgos = analizar(solicitud)
    except ErrorAnalisis as error:
        log.error("analisis=%s tree=%s error=%s", id_analisis, solicitud.tree_hash, error)
        # Al cliente no se le exponen detalles internos
        raise HTTPException(status_code=503, detail=f"No fue posible completar el análisis ({id_analisis})")

    aprobado = not any(bloquea_commit(hallazgo) for hallazgo in hallazgos)

    # Registro de cada análisis para auditoría
    log.info(
        "analisis=%s tree=%s archivos=%d aprobado=%s hallazgos=%d",
        id_analisis,
        solicitud.tree_hash,
        len(solicitud.archivos),
        aprobado,
        len(hallazgos),
    )
    return ResultadoAnalisis(
        id_analisis=id_analisis,
        aprobado=aprobado,
        modelo=ajustes.ANTHROPIC_MODEL,
        version_prompt=VERSION_PROMPT,
        severidad_bloqueo=ajustes.SEVERIDAD_BLOQUEO,
        hallazgos=hallazgos,
    )
