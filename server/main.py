"""API del servidor de análisis."""

import logging
import uuid

from fastapi import FastAPI

from server.analizador import analizar
from server.modelos import ResultadoAnalisis, SolicitudAnalisis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("appsec")

app = FastAPI(title="AppSec GenAI", version="0.1.0")


@app.get("/health")
def health():
    return {"estado": "ok"}


@app.post("/analyze", response_model=ResultadoAnalisis)
def analyze(solicitud: SolicitudAnalisis):
    id_analisis = str(uuid.uuid4())
    hallazgos = analizar(solicitud)
    aprobado = not hallazgos

    # Registro de cada análisis para auditoría
    log.info(
        "analisis=%s tree=%s archivos=%d aprobado=%s hallazgos=%d",
        id_analisis,
        solicitud.tree_hash,
        len(solicitud.archivos),
        aprobado,
        len(hallazgos),
    )
    return ResultadoAnalisis(id_analisis=id_analisis, aprobado=aprobado, hallazgos=hallazgos)
