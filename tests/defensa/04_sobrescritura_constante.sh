#!/usr/bin/env bash
# DEMO: contraste para explicar una sobrescritura segura.
# ANALYZER-ARGS: dato_externo
# Primero se recibe un argumento, pero nunca llega al sink.
# La variable se reemplaza por una constante antes de utilizarse.

entrada="$1"                  # Fuente inicial: el dato sí es externo.
intermedia="$entrada"         # El taint se propaga a otra variable.
intermedia="valor_constante"  # Sobrescritura: se descarta el dato externo.

crear_mensaje() {
    local mensaje="$1"
    printf '%s\\n' "$mensaje"  # Uso citado de una constante conocida.
}

crear_mensaje "$intermedia"
# No se usa eval, bash -c ni un comando dinámico después de la sobrescritura.
printf 'El flujo terminó sin ejecutar código recibido.\n'
