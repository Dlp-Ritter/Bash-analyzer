# monitor.sh - Monitor de ejecucion (Iteracion 2)
#
# Ejecuta el script analizado en un proceso Bash hijo con un trap DEBUG que
# invoca al motor de propagacion antes de cada comando. El monitor se inyecta
# con BASH_ENV (sin tocar el script analizado) y escribe los eventos en un
# archivo temporal que este modulo lee al terminar.
#
# AVISO: este modo EJECUTA el script. Debe usarse solo en un entorno aislado.

AZ_EVENTS=()      # eventos deduplicados (TSV de 7 columnas)
MONITOR_RC=0      # codigo de salida del script analizado
AZ_TARGET=""
AZ_RECURSIVE=0
AZ_MONFILE=""

# Manejador del trap DEBUG: _az_trap <archivo> <linea> <funciones> <comando> <estado-previo>
_az_trap() {
  local _az_o=$- IFS=$' \t\n' _az_f _az_d=0
  local -a _az_fn=() _az_br=()
  set +eux
  _az_br=("${BASH_REMATCH[@]}")   # el manejador usa [[ =~ ]]: se restaura al salir (transparencia)
  # Objetivo: el script principal; con -r tambien cualquier archivo regular que se
  # cargue (source) o que corra en un hijo (el monitor se hereda por BASH_ENV).
  if [[ $1 == "$AZ_TARGET" ]] || { ((AZ_RECURSIVE)) && [[ $1 != "$AZ_MONFILE" && -f $1 ]]; }; then
    read -ra _az_fn <<<"$3"
    for _az_f in "${_az_fn[@]}"; do
      [[ $_az_f == main || $_az_f == source || $_az_f == . ]] || _az_d=$((_az_d + 1))
    done
    _az_prop_process "$1" "$2" "$4" "$_az_d" "$5"
  fi
  { BASH_REMATCH=("${_az_br[@]}"); } 2>/dev/null || :
  [[ $_az_o == *e* ]] && set -e
  [[ $_az_o == *u* ]] && set -u
  [[ $_az_o == *x* ]] && set -x
  return 0
}

# monitor_build_file <ruta>  -> genera el archivo que se carga via BASH_ENV
monitor_build_file() {
  local out=$1
  local -a vars funcs
  AZ_TARGET=$2
  mapfile -t vars < <(compgen -v AZ_)
  mapfile -t funcs < <(compgen -A function _az_)
  {
    # Con -r el monitor se hereda: los scripts hijos (bash otro.sh) se analizan igual.
    ((AZ_RECURSIVE)) || printf 'unset BASH_ENV\n'
    declare -p "${vars[@]}" 2>/dev/null | sed 's/^declare -\([A-Za-z-]*\) /declare -g\1 /; s/^declare -g- /declare -g /'
    declare -f "${funcs[@]}"
    cat <<'INIT'
AZ_INITIAL_ENV=()
for _az_n in $(compgen -e); do
  case $_az_n in AZ_*|ANALYZER_*|BASH_ENV|_) ;; *) AZ_INITIAL_ENV[$_az_n]=1 ;; esac
done
unset _az_n
AZ_TARGET=$0
exec {AZ_FD}>>"$ANALYZER_EVENTS"
((AZ_RECURSIVE)) || unset ANALYZER_EVENTS
set -T
trap '_az_u=$_ _az_s=$?; _az_trap "${BASH_SOURCE[0]}" "$LINENO" "${FUNCNAME[*]-}" "$BASH_COMMAND" "$_az_s"; : "$_az_u"' DEBUG
INIT
  } >"$out"
}

# monitor_run <script> [args...]  -> llena AZ_EVENTS y MONITOR_RC
monitor_run() {
  local script=$1 tmp mon ev kind f ln a b c p key
  shift
  local seen=$'\n'
  tmp=$(mktemp -d) || return 2
  mon=$tmp/monitor.sh
  ev=$tmp/events.tsv
  : >"$ev"
  AZ_EVENTS=()
  AZ_MODE=${OPT_MODE:-strict}
  AZ_RECURSIVE=${OPT_RECURSIVE:-0}
  AZ_MONFILE=$mon
  monitor_build_file "$mon" "$script"

  local -a runner=(env "BASH_ENV=$mon" "ANALYZER_EVENTS=$ev" "$BASH" "$script" "$@")
  if ((${OPT_SCRIPT_OUTPUT:-1})); then
    "${runner[@]}" >&2
  else
    "${runner[@]}" >/dev/null
  fi
  MONITOR_RC=$?

  while IFS=$'\t' read -r kind f ln a b c p; do
    [[ -z $kind ]] && continue
    if [[ $kind == SOURCE ]]; then key="$kind|$f|$ln|$a|$b"; else key="$kind|$f|$ln|$a|$b|$c"; fi
    [[ $seen == *$'\n'"$key"$'\n'* ]] && continue
    seen+="$key"$'\n'
    AZ_EVENTS+=("$kind"$'\t'"$f"$'\t'"$ln"$'\t'"$a"$'\t'"$b"$'\t'"$c"$'\t'"$p")
  done <"$ev"
  rm -rf -- "$tmp"
  return 0
}
