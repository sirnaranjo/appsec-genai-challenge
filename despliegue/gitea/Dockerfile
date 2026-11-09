# Gitea con Python, las dependencias del verificador y una copia fija de verifier/, que se ejecuta como hook
FROM gitea/gitea:1.24.7

RUN apk add --no-cache python3 py3-cryptography py3-yaml py3-pip \
    && pip install --no-cache-dir --break-system-packages identify==2.6.20

# Copiado y no montado: un cambio en la carpeta del equipo no altera el hook hasta reconstruir la imagen
COPY verifier/ /appsec/verifier/
