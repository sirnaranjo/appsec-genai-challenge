"""API del servidor de análisis."""

import logging
import uuid

from fastapi import Depends, FastAPI, HTTPException

from server import ajustes
from server.analizador import VERSION_PROMPT, ErrorAnalisis, analizar
from server.autenticacion import Usuario, usuario_autenticado
from server.modelos import ResultadoAnalisis, SolicitudAnalisis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("appsec")

app = FastAPI(title="AppSec GenAI", version="0.3.0")

SEVERIDADES = ["BAJA", "MEDIA", "ALTA", "CRITICA"]

if not ajustes.USUARIOS_PERMITIDOS:
    log.warning("USUARIOS_PERMITIDOS está vacío: ningún usuario podrá usar el análisis")


def bloquea_commit(hallazgo):
    return SEVERIDADES.index(hallazgo.severidad) >= SEVERIDADES.index(ajustes.SEVERIDAD_BLOQUEO)


@app.get("/health")
def health():
    return {"estado": "ok"}


@app.get("/auth/config")
def auth_config():
    # El client_id de la OAuth App es público; así el desarrollador solo configura la URL del servidor
    if not ajustes.GITHUB_OAUTH_CLIENT_ID:
        raise HTTPException(status_code=503, detail="La autenticación no está configurada en el servidor")
    return {"client_id": ajustes.GITHUB_OAUTH_CLIENT_ID}


@app.get("/auth/me", response_model=Usuario)
def auth_me(usuario: Usuario = Depends(usuario_autenticado)):
    return usuario


@app.post("/analyze", response_model=ResultadoAnalisis)
def analyze(solicitud: SolicitudAnalisis, usuario: Usuario = Depends(usuario_autenticado)):
    id_analisis = str(uuid.uuid4())
    try:
        hallazgos = analizar(solicitud)
    except ErrorAnalisis as error:
        log.error("analisis=%s usuario=%s tree=%s error=%s", id_analisis, usuario.login, solicitud.tree_hash, error)
        # Al cliente no se le exponen detalles internos
        raise HTTPException(status_code=503, detail=f"No fue posible completar el análisis ({id_analisis})")

    aprobado = not any(bloquea_commit(hallazgo) for hallazgo in hallazgos)

    # Registro de cada análisis para auditoría, con la identidad verificada en GitHub
    log.info(
        "analisis=%s usuario=%s autor_git=%s tree=%s archivos=%d aprobado=%s hallazgos=%d",
        id_analisis,
        usuario.login,
        solicitud.autor_git,
        solicitud.tree_hash,
        len(solicitud.archivos),
        aprobado,
        len(hallazgos),
    )
    return ResultadoAnalisis(
        id_analisis=id_analisis,
        aprobado=aprobado,
        usuario=usuario.login,
        modelo=ajustes.ANTHROPIC_MODEL,
        version_prompt=VERSION_PROMPT,
        severidad_bloqueo=ajustes.SEVERIDAD_BLOQUEO,
        hallazgos=hallazgos,
    )
