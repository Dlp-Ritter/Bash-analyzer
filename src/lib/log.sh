# log.sh - bitacora local de la sesion (todo queda en el sistema de archivos local)

log_event() {
  local dir=${ANALYZER_LOG_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/bash-analyzer}
  {
    mkdir -p -- "$dir" &&
      printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*" >>"$dir/analyzer.log"
  } 2>/dev/null || true
}
