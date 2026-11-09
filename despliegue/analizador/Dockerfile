# Servidor de análisis (FastAPI). Las llaves y el .env no se copian a la imagen: se entregan al iniciar
# Recibe las peticiones del hook pre-commit, consulta a Claude y genera los recibos de cada análisis
FROM python:3.12-slim

WORKDIR /app
# Primero las dependencias: si solo cambia el código, Docker reutiliza esta capa
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt
COPY server ./server

EXPOSE 8000
# 0.0.0.0: acepta conexiones desde fuera del contenedor (el puerto publicado en docker-compose.yml)
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
