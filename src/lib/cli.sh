# cli.sh - Interfaz de linea de comandos (CU01)
#
# Codigos de salida: 0 correcto; 2 error de uso o de archivo;
# 1 si el modo strict encuentra alertas CRITICAS.

ANALYZER_VERSION="1.0.0"

OPT_MODE="strict"
OPT_RECURSIVE=0
OPT_VERBOSE=0
OPT_EXPORT=""
OPT_FORMAT="text"
OPT_SCRIPT=""
OPT_STATIC=0
OPT_QUIET=0
OPT_SCRIPT_OUTPUT=1
OPT_ALLOW_EXECUTION=0
OPT_ARGS=()

_err() { msgln "$@" >&2; }

# cli_show_manual imprime el manual embebido o la copia de desarrollo.
cli_show_manual() {
  if declare -F _embedded_manual >/dev/null 2>&1; then
    _embedded_manual
    return 0
  fi

  local manual="${ANALYZER_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}/../docs/manual de usuario.txt"
  if [[ -r $manual ]]; then
    cat -- "$manual"
    return 0
  fi

  _err err_manual_missing
  return 2
}

# cli_validate_file <archivo>  -> 0 si es un script Bash legible
cli_validate_file() {
  local f=$1 first=""
  if [[ ! -e $f ]]; then _err err_no_file "$f"; return 2; fi
  if [[ ! -f $f || ! -r $f ]]; then _err err_not_readable "$f"; return 2; fi
  # rechaza binarios (bytes nulos)
  if ! LC_ALL=C tr -d '\000' <"$f" | cmp -s - "$f"; then
    _err err_not_bash "$f"
    return 2
  fi
  IFS= read -r first <"$f" || true
  if [[ $first =~ ^#!.*(/|[[:space:]])(ba|da|a)?sh([[:space:]]|$) || $f == *.sh || $f == *.bash ]]; then
    return 0
  fi
  _err err_not_bash "$f"
  return 2
}

cli_parse_args() {
  local a v
  while (($#)); do
    a=$1
    shift
    case $a in
      -h | --help) msgln usage; exit 0 ;;
      --manual) cli_show_manual; exit 0 ;;
      -V | --version) printf 'analyzer %s\n' "$ANALYZER_VERSION"; exit 0 ;;
      --lang=*)
        v=${a#*=}
        [[ $v == es || $v == en ]] || { _err err_bad_value "$v" --lang; exit 2; }
        ANALYZER_LANG=$v
        ;;
      --mode=*)
        v=${a#*=}
        [[ $v == strict || $v == conservative ]] || { _err err_bad_value "$v" --mode; exit 2; }
        OPT_MODE=$v
        ;;
      --format=*)
        v=${a#*=}
        [[ $v == text || $v == tsv ]] || { _err err_bad_value "$v" --format; exit 2; }
        OPT_FORMAT=$v
        ;;
      -r | --recursive) OPT_RECURSIVE=1 ;;
      -v | --verbose) OPT_VERBOSE=1 ;;
      --export=*)
        v=${a#*=}
        [[ $v == json ]] || { _err err_bad_value "$v" --export; exit 2; }
        OPT_EXPORT=$v
        if (($# == 0)) || [[ $1 == -* ]]; then _err err_export_missing; exit 2; fi
        OPT_EXPORT_FILE=$1   # el siguiente argumento es el archivo de salida
        shift
        ;;
      --static) OPT_STATIC=1 ;;
      --yes | --allow-execution) OPT_ALLOW_EXECUTION=1 ;;
      -q | --quiet) OPT_QUIET=1 ;;
      --no-script-output) OPT_SCRIPT_OUTPUT=0 ;;
      --) OPT_SCRIPT=${1-}; (($#)) && shift; OPT_ARGS=("$@"); break ;;
      -*) _err err_unknown_opt "$a"; exit 2 ;;
      *) OPT_SCRIPT=$a; OPT_ARGS=("$@"); break ;;
    esac
  done
}

# cli_check_deps: comandos externos que usa el analizador (todos de coreutils/sed)
cli_check_deps() {
  local c
  for c in cat cmp date env mkdir mktemp rm sed tr; do
    command -v "$c" >/dev/null 2>&1 || { _err err_missing_cmd "$c"; return 2; }
  done
}

analyzer_main() {
  cli_parse_args "$@"
  cli_check_deps || return $?
  if [[ -z $OPT_SCRIPT ]]; then
    _err err_missing_file
    msgln usage >&2
    return 2
  fi
  cli_validate_file "$OPT_SCRIPT" || return $?
  if ! rules_load; then
    _err err_no_rules
    return 2
  fi

  if ((OPT_STATIC)); then
    [[ -n $OPT_EXPORT_FILE ]] && _err warn_export_static
    ((OPT_RECURSIVE)) && _err warn_recursive_static
    log_event "inicio analisis estatico archivo=$OPT_SCRIPT modo=$OPT_MODE"
    sources_detect "$OPT_SCRIPT"
    if [[ $OPT_FORMAT == tsv ]]; then
      sources_report_tsv
    else
      sources_report_text "$OPT_SCRIPT"
    fi
    log_event "fin analisis fuentes=${#AZ_SOURCES[@]}"
    return 0
  fi

  if (( ! OPT_ALLOW_EXECUTION )) && [[ ${ANALYZER_ALLOW_EXECUTION:-} != 1 ]]; then
    if [[ ! -t 0 ]]; then
      _err err_exec_confirmation
      return 2
    fi
    _err warn_exec_confirm
    IFS= read -r -p "$(msg confirm_exec) " _az_answer || _az_answer=""
    [[ $_az_answer == [yYsS] || $_az_answer == [yYsS][eE][sS] ]] || {
      _err err_exec_cancelled
      return 2
    }
  fi
  ((OPT_QUIET)) || _err warn_exec
  log_event "inicio analisis dinamico archivo=$OPT_SCRIPT modo=$OPT_MODE"
  monitor_run "$OPT_SCRIPT" "${OPT_ARGS[@]}"
  report_filter
  if [[ $OPT_FORMAT == tsv ]]; then
    propagation_report_tsv
  else
    report_text "$OPT_SCRIPT"
  fi
  report_export "$OPT_SCRIPT"
  log_event "fin analisis eventos=${#AZ_EVENTS[@]} alertas=${#AZ_FINDINGS[@]} rc=$MONITOR_RC"
  report_exit_code
  return $?
}
