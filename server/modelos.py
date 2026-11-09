"""Contrato de la API: lo que recibe y lo que responde el servidor."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Límites por archivo y por commit: acotan el costo y la espera del análisis
MAX_CARACTERES_ARCHIVO = 100_000
MAX_CARACTERES_TOTAL = 500_000
# Hash de Git: 40 caracteres (SHA-1) o 64 (SHA-256)
PATRON_HASH = r"^([0-9a-f]{40}|[0-9a-f]{64})$"


class Archivo(BaseModel):
    ruta: str = Field(min_length=1, max_length=500)
    # diff: solo los cambios con contexto; completo: el archivo entero, cuando no hay cambios en staging
    tipo: Literal["diff", "completo"]
    contenido: str = Field(max_length=MAX_CARACTERES_ARCHIVO)


class SolicitudAnalisis(BaseModel):
    # Se rechazan campos desconocidos
    model_config = ConfigDict(extra="forbid")

    # Hash del contenido completo que tendrá el commit (git write-tree)
    tree_hash: str = Field(pattern=PATRON_HASH)
    # Hash del contenido del commit padre. None solo en el primer commit del repositorio
    tree_base: str | None = Field(default=None, pattern=PATRON_HASH)
    # Datos informativos para el registro de auditoría; no influyen en la decisión
    rama: str | None = None
    commit_padre: str | None = None
    repositorio: str | None = None
    autor_git: str | None = None
    # Puede venir vacía si el commit no cambia código: igual se emite el recibo del commit
    archivos: list[Archivo] = Field(max_length=200)

    # Los límites del cliente se validan de nuevo: el servidor no confía en el cliente
    @model_validator(mode="after")
    def validar_tamano_total(self):
        total = sum(len(archivo.contenido) for archivo in self.archivos)
        if total > MAX_CARACTERES_TOTAL:
            raise ValueError(f"El cambio supera el máximo de {MAX_CARACTERES_TOTAL} caracteres")
        return self


# Formato de cada vulnerabilidad: lo deben cumplir la respuesta del LLM y el pre-filtro
class Hallazgo(BaseModel):
    # Categoría del OWASP Top 10 2021, o "Manipulacion del analisis"
    owasp: str
    titulo: str
    archivo: str
    # None cuando no corresponde a una línea, por ejemplo si el problema está en el nombre del archivo
    linea: int | None = None
    severidad: Literal["BAJA", "MEDIA", "ALTA", "CRITICA"]
    riesgo: str
    solucion: str
    codigo_sugerido: str | None = None


class ResultadoAnalisis(BaseModel):
    id_analisis: str
    aprobado: bool
    usuario: str
    modelo: str
    version_prompt: str
    severidad_bloqueo: str
    hallazgos: list[Hallazgo]
    # Solo se emite si el análisis fue aprobado
    recibo: str | None = None
