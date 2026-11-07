#!/usr/bin/env bash
# DEMO: flujo completo de un argumento externo hasta eval.
# ANALYZER-ARGS: echo DEFENSA_EVAL
# La entrada es deliberadamente inocua: solo imprime un texto.
# El riesgo demostrado es que eval interpreta la entrada como código.

entrada="$1"                 # Fuente: argumento posicional $1.
preparada="prefijo-$entrada" # Propagación mediante interpolación.
comando="printf '%s\\n' \"$preparada\"" # Nueva variable contaminada.

mostrar_comando() {
    # El parámetro conserva el flujo contaminado dentro de la función.
    local recibido="$1"
    printf 'Se ejecutará una demostración controlada.\n'
    eval "$recibido"          # Sink EVAL: CWE-78, severidad crítica.
}

mostrar_comando "$comando"
