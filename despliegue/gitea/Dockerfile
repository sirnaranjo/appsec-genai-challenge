# Gitea con Python y las dependencias del verificador, para ejecutar verifier/pre_receive.py como hook
FROM gitea/gitea:1.24.7

RUN apk add --no-cache python3 py3-cryptography py3-yaml py3-pip \
    && pip install --no-cache-dir --break-system-packages identify==2.6.20
