#!/usr/bin/env bash
# DEMO: dos hallazgos diferentes en una ejecución controlada.
# ANALYZER-ARGS: echo DEFENSA_SUBSHELL
# La entrada no toca archivos ni red; solo contiene texto seguro.
# Se demuestra que una variable puede ser riesgosa por dos motivos.

entrada="$1"                    # Fuente externa: argumento posicional.
archivo="$entrada.txt"          # Propagación hacia una variable local.
comando="printf '%s\\n' \"$archivo\"" # Comando para el shell hijo.

mostrar_nombre() {
    # La expansión sin comillas puede separar palabras y argumentos.
    printf 'Nombre recibido: '
    printf '%s\\n' $archivo       # Sink UNQUOTED: CWE-88, severidad alta.
}

ejecutar_subshell() {
    # bash -c interpreta su argumento como código de shell.
    bash -c "$comando"           # Sink SUBSHELL: CWE-78, crítico.
}

mostrar_nombre
ejecutar_subshell
