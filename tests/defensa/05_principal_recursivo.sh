#!/usr/bin/env bash
# DEMO: análisis recursivo de un archivo principal y uno secundario.
# ANALYZER-ARGS: echo DEFENSA_RECURSIVA
# ANALYZER-OPTS: --recursive
# La ruta del secundario es literal para que el analizador pueda resolverla.

entrada="$1"                    # Fuente que nace en el script principal.
principal="$entrada"             # Propagación local en el archivo principal.
modo="recursivo"                 # Metadato constante de la demostración.
origen="principal"               # Identifica el primer archivo del flujo.
if [[ -z "$principal" ]]; then
    printf 'Se requiere un argumento de demostración.\n'
    exit 1
fi
printf 'Archivo %s preparado en modo %s.\n' "$origen" "$modo"

# El secundario recibe el mismo dato y contiene el sink de la demostración.
source tests/defensa/05_secundario.sh "$principal"
printf 'Regreso desde el archivo secundario.\n'
