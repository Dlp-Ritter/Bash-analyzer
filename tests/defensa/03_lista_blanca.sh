#!/usr/bin/env bash
# DEMO: validación explícita mediante una lista blanca acotada.
# ANALYZER-ARGS: echo
# La entrada válida solo puede contener letras minúsculas.
# En strict se puede reportar SANITIZED; en conservative se filtra.

entrada="$1"                         # Fuente externa: argumento posicional.
[[ $entrada =~ ^[a-z]+$ ]] || {
    printf 'Entrada rechazada por la lista blanca.\n'
    exit 1
}

comando="$entrada"                    # Flujo validado hacia un comando.
printf 'Entrada aceptada por la demostración.\n'
eval "$comando"                      # Sink EVAL; la validación es observable.
