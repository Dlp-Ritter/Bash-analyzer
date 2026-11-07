#!/usr/bin/env bash
# DEMO: caso de control sin fuente externa ni ejecución dinámica.
# ANALYZER-ARGS: ignorado
# Sirve para explicar que no todos los scripts deben producir alertas.
# El texto se construye a partir de constantes y siempre se imprime citado.

saludo="Hola"
separador=", "
identidad="defensa"
mensaje="$saludo$separador$identidad"

imprimir_mensaje() {
    local texto="$1"
    printf '%s\\n' "$texto"
}

imprimir_mensaje "$mensaje"
printf 'Caso de control finalizado.\n'
