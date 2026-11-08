"""Registro de auditoría de todos los análisis, aprobados y rechazados, en SQLite."""

import json
import sqlite3
from datetime import datetime, timezone

from server import ajustes

ESQUEMA = """
CREATE TABLE IF NOT EXISTS analisis (
    id TEXT PRIMARY KEY,
    fecha TEXT NOT NULL,
    usuario TEXT NOT NULL,
    usuario_id INTEGER NOT NULL,
    autor_git TEXT,
    repositorio TEXT,
    rama TEXT,
    commit_padre TEXT,
    tree_hash TEXT NOT NULL,
    tree_base TEXT,
    huella_contenido TEXT NOT NULL,
    archivos TEXT NOT NULL,
    aprobado INTEGER NOT NULL,
    hallazgos TEXT NOT NULL,
    modelo TEXT NOT NULL,
    version_prompt TEXT NOT NULL,
    recibo TEXT
);
CREATE INDEX IF NOT EXISTS idx_analisis_tree ON analisis (tree_hash);
"""


def conectar():
    ajustes.RUTA_BASE_DATOS.parent.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(ajustes.RUTA_BASE_DATOS)
    conexion.executescript(ESQUEMA)
    return conexion


def guardar(id_analisis, solicitud, usuario, aprobado, hallazgos, huella, modelo, version_prompt, recibo):
    fila = (
        id_analisis,
        datetime.now(timezone.utc).isoformat(),
        usuario.login,
        usuario.id,
        solicitud.autor_git,
        solicitud.repositorio,
        solicitud.rama,
        solicitud.commit_padre,
        solicitud.tree_hash,
        solicitud.tree_base,
        huella,
        json.dumps([archivo.ruta for archivo in solicitud.archivos]),
        int(aprobado),
        json.dumps([hallazgo.model_dump() for hallazgo in hallazgos], ensure_ascii=False),
        modelo,
        version_prompt,
        recibo,
    )
    # Consultas parametrizadas: ningún dato del cliente se concatena en el SQL
    with conectar() as conexion:
        conexion.execute(f"INSERT INTO analisis VALUES ({', '.join('?' * len(fila))})", fila)
    conexion.close()


def buscar_por_tree(tree_hash):
    with conectar() as conexion:
        conexion.row_factory = sqlite3.Row
        filas = conexion.execute(
            "SELECT * FROM analisis WHERE tree_hash = ? ORDER BY fecha DESC", (tree_hash,)
        ).fetchall()
    conexion.close()
    return [dict(fila) for fila in filas]
