"""API del servidor de análisis."""

import logging
import uuid

from fastapi import Depends, FastAPI, HTTPException

from server import ajustes, recibos, registro
from server.analizador import VERSION_PROMPT, ErrorAnalisis, analizar
from server.autenticacion import Usuario, usuario_autenticado
from server.modelos import ResultadoAnalisis, SolicitudAnalisis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("appsec")

app = FastAPI(title="AppSec GenAI", version="0.4.0")

# De menor a mayor: la posición en la lista permite compararlas
SEVERIDADES = ["BAJA", "MEDIA", "ALTA", "CRITICA"]

if not ajustes.USUARIOS_PERMITIDOS:
    log.warning("USUARIOS_PERMITIDOS está vacío: ningún usuario podrá usar el análisis")


def bloquea_commit(hallazgo):
    # Bloquea si la severidad del hallazgo es igual o mayor que SEVERIDAD_BLOQUEO
    return SEVERIDADES.index(hallazgo.severidad) >= SEVERIDADES.index(ajustes.SEVERIDAD_BLOQUEO)


# Comprobación de que el servidor está en línea
@app.get("/health")
def health():
    return {"estado": "ok"}


@app.get("/auth/config")
def auth_config():
    # El client_id de la OAuth App es público; así el desarrollador solo configura la URL del servidor
    if not ajustes.GITHUB_OAUTH_CLIENT_ID:
        raise HTTPException(status_code=503, detail="La autenticación no está configurada en el servidor")
    return {"client_id": ajustes.GITHUB_OAUTH_CLIENT_ID}


# Usuario dueño del token; hooks/login.py lo usa para confirmar la sesión
@app.get("/auth/me", response_model=Usuario)
def auth_me(usuario: Usuario = Depends(usuario_autenticado)):
    return usuario


@app.post("/analyze", response_model=ResultadoAnalisis)
def analyze(solicitud: SolicitudAnalisis, usuario: Usuario = Depends(usuario_autenticado)):
    # Identificador del análisis: aparece en el recibo, en el registro y en los mensajes de error
    id_analisis = str(uuid.uuid4())
    modelo = ajustes.ANTHROPIC_MODEL
    try:
        # Un commit sin archivos de código no necesita LLM, pero igual recibe su recibo
        hallazgos = analizar(solicitud) if solicitud.archivos else []
        # Aprobado si ningún hallazgo alcanza la severidad de bloqueo; los demás quedan como advertencias
        aprobado = not any(bloquea_commit(hallazgo) for hallazgo in hallazgos)
        recibo = None
        # Solo un análisis aprobado recibe recibo; len(hallazgos) es el número de advertencias
        if aprobado:
            recibo = recibos.emitir(solicitud, usuario, id_analisis, len(hallazgos), modelo, VERSION_PROMPT)
    except (ErrorAnalisis, recibos.ErrorRecibo) as error:
        log.error("analisis=%s usuario=%s tree=%s error=%s", id_analisis, usuario.login, solicitud.tree_hash, error)
        # Al cliente no se le exponen detalles internos
        raise HTTPException(status_code=503, detail=f"No fue posible completar el análisis ({id_analisis})")

    # Registro de cada análisis para auditoría, con la identidad verificada en GitHub
    huella = recibos.huella_contenido(solicitud.archivos)
    registro.guardar(id_analisis, solicitud, usuario, aprobado, hallazgos, huella, modelo, VERSION_PROMPT, recibo)
    # autor_git es el que declara Git y puede ser falso; usuario es el verificado con GitHub
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
        modelo=modelo,
        version_prompt=VERSION_PROMPT,
        # Umbral aplicado: el cliente lo usa para separar bloqueos de advertencias
        severidad_bloqueo=ajustes.SEVERIDAD_BLOQUEO,
        hallazgos=hallazgos,
        recibo=recibo,
    )
