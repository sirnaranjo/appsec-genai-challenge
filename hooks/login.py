"""Inicio de sesión con GitHub para usar el hook de análisis.

Uso:
    python hooks/login.py            inicia sesión
    python hooks/login.py --estado   muestra con qué usuario hay sesión iniciada
    python hooks/login.py --salir    cierra la sesión
"""

import argparse
import sys
import webbrowser

import autenticacion
import cliente_api


def iniciar_sesion():
    client_id = cliente_api.configuracion_autenticacion()["client_id"]
    solicitud = autenticacion.solicitar_codigo(client_id)

    print(f"Abre {solicitud['verification_uri']} e ingresa el código: {solicitud['user_code']}")
    print("Esperando la autorización en GitHub...")
    webbrowser.open(solicitud["verification_uri"])

    token = autenticacion.esperar_autorizacion(client_id, solicitud)
    # Antes de guardarlo se confirma con el servidor que el usuario está autorizado
    usuario = cliente_api.usuario_actual(token)
    autenticacion.guardar_token(token)
    print(f"Sesión iniciada como {usuario['login']}.")


def mostrar_estado():
    token = autenticacion.token_guardado()
    if not token:
        print("No hay una sesión iniciada.")
        return
    print(f"Sesión iniciada como {cliente_api.usuario_actual(token)['login']}.")


def main():
    parser = argparse.ArgumentParser(description="Sesión de GitHub para el hook de análisis de seguridad")
    grupo = parser.add_mutually_exclusive_group()
    grupo.add_argument("--estado", action="store_true", help="muestra el usuario con sesión iniciada")
    grupo.add_argument("--salir", action="store_true", help="cierra la sesión")
    argumentos = parser.parse_args()

    try:
        if argumentos.salir:
            autenticacion.borrar_token()
            print("Sesión cerrada.")
        elif argumentos.estado:
            mostrar_estado()
        else:
            iniciar_sesion()
    except (autenticacion.ErrorLogin, cliente_api.ErrorServidor) as error:
        print(f"Error: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
