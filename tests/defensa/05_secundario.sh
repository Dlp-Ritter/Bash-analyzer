#!/usr/bin/env bash
# DEMO: parte secundaria del caso recursivo.
# Este archivo se carga mediante source desde 05_principal_recursivo.sh.
# No realiza operaciones de red, archivos peligrosos ni privilegios elevados.

recibido="$1"                    # Parámetro recibido desde el principal.
transformado="printf '%s\\n' \"$recibido\"" # Propagación en el secundario.

informar() {
    local comando_local="$1"
    printf 'El sink está en el archivo secundario.\n'
    eval "$comando_local"         # Sink EVAL: CWE-78, crítico.
}

informar "$transformado"
