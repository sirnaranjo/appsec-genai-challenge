"""Contrato de la API: lo que recibe y lo que responde el servidor."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_CARACTERES_ARCHIVO = 100_000
MAX_CARACTERES_TOTAL = 500_000


class Archivo(BaseModel):
    ruta: str = Field(min_length=1, max_length=500)
    tipo: Literal["diff", "completo"]
    contenido: str = Field(max_length=MAX_CARACTERES_ARCHIVO)


class SolicitudAnalisis(BaseModel):
    # Se rechazan campos desconocidos
    model_config = ConfigDict(extra="forbid")

    tree_hash: str = Field(pattern=r"^([0-9a-f]{40}|[0-9a-f]{64})$")
    rama: str | None = None
    commit_padre: str | None = None
    repositorio: str | None = None
    autor_git: str | None = None
    archivos: list[Archivo] = Field(min_length=1, max_length=200)

    # Los límites del cliente se validan de nuevo: el servidor no confía en el cliente
    @model_validator(mode="after")
    def validar_tamano_total(self):
        total = sum(len(archivo.contenido) for archivo in self.archivos)
        if total > MAX_CARACTERES_TOTAL:
            raise ValueError(f"El cambio supera el máximo de {MAX_CARACTERES_TOTAL} caracteres")
        return self


class Hallazgo(BaseModel):
    owasp: str
    titulo: str
    archivo: str
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
