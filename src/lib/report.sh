# report.sh - Clasificador, filtro por modo y salidas (Iteracion 4)
#
# Recibe los eventos del monitor (AZ_EVENTS), clasifica las alertas segun el
# catalogo (severidad y CWE), aplica el modo strict/conservative y produce la
# salida de terminal, el codigo de salida y la exportacion JSON.

AZ_FINDINGS=()   # severidad TAB cwe TAB archivo TAB linea TAB clave TAB var TAB cmd TAB ruta
declare -gA AZ_SEV_RANK=([CRITICAL]=4 [HIGH]=3 [MEDIUM]=2 [INFO]=1)
OPT_EXPORT_FILE=""
declare -gA AZ_IGNORE=() AZ_IGNORE_LOADED=()
AZ_FILES=()        # scripts con actividad observada (principal primero)
AZ_WARNINGS=()     # avisos: archivo TAB linea TAB comando TAB destino
AZ_EXCLUDED=0      # lineas excluidas por directiva ignore-rule

# report_key <sink-del-evento> -> clave de clasificacion del catalogo
report_key() {
  case $1 in
    */SAN) printf SANITIZED ;;
    */LOW) printf LOWRISK ;;
    */CONST) printf CONSTANT ;;
    *) printf '%s' "$1" ;;
  esac
}

# Directivas "# ignore-rule" / "# ignore-rule:<id>[,<id>]" (CU04). Un comentario solo
# en su linea aplica a la linea siguiente; al final de una linea, a esa misma linea.
_report_load_ignore() {
  local file=$1 i line ids target
  local -a L=()
  local re='(^|[[:space:]])#[[:space:]]*ignore-rule(:([A-Za-z0-9_,/-]+))?([[:space:]]|$)'
  [[ -n ${AZ_IGNORE_LOADED[$file]-} ]] && return 0
  AZ_IGNORE_LOADED[$file]=1
  [[ -r $file ]] || return 0
  mapfile -t L <"$file"
  for ((i = 0; i < ${#L[@]}; i++)); do
    line=${L[i]}
    [[ $line =~ $re ]] || continue
    ids=${BASH_REMATCH[3]:-*}
    if [[ $line =~ ^[[:space:]]*# ]]; then target=$((i + 2)); else target=$((i + 1)); fi
    AZ_IGNORE["$file|$target"]+=" $ids"
  done
}

# _report_ignored <archivo> <linea> <sink-del-evento> -> 0 si una directiva lo excluye
_report_ignored() {
  local ids tok key base=${3%%/*}
  local -a toks=()
  _report_load_ignore "$1"
  ids=${AZ_IGNORE["$1|$2"]-}
  [[ -n $ids ]] || return 1
  key=$(report_key "$3")
  read -ra toks <<<"${ids//,/ }"   # sin expansion de comodines ("*")
  for tok in "${toks[@]}"; do
    tok=${tok^^}
    [[ $tok == '*' || $tok == "$key" || $tok == "$base" ]] && return 0
  done
  return 1
}

# report_filter: aplica ignore-rule, asigna severidad/CWE, aplica el modo y deja
# AZ_FINDINGS (principal primero), AZ_FILES, AZ_WARNINGS y AZ_EXCLUDED.
# conservative solo conserva CRITICAL y HIGH; strict conserva todo.
report_filter() {
  local e kind f ln a b c p r key sev cwe seen=$'\n' ex=$'\n'
  local -a kept=() main=() other=()
  AZ_FINDINGS=() AZ_FILES=() AZ_WARNINGS=() AZ_EXCLUDED=0
  AZ_FILES=("$OPT_SCRIPT")
  seen+="$OPT_SCRIPT"$'\n'
  for e in "${AZ_EVENTS[@]}"; do
    IFS=$'\t' read -r kind f ln a b c p <<<"$e"
    if [[ $kind != UNRESOLVED && $seen != *$'\n'"$f"$'\n'* ]]; then
      seen+="$f"$'\n'
      AZ_FILES+=("$f")
    fi
    if [[ $kind == UNRESOLVED ]]; then
      AZ_WARNINGS+=("$f"$'\t'"$ln"$'\t'"$a"$'\t'"$b")
      kept+=("$e")
      continue
    fi
    if [[ $kind != ALERT ]]; then kept+=("$e"); continue; fi
    if _report_ignored "$f" "$ln" "$a"; then
      kept+=("IGNORED"$'\t'"${e#*$'\t'}")
      if [[ $ex != *$'\n'"$f|$ln"$'\n'* ]]; then ex+="$f|$ln"$'\n'; AZ_EXCLUDED=$((AZ_EXCLUDED + 1)); fi
      continue
    fi
    key=$(report_key "$a")
    sev=$(rules_sink_field SEV "$key")
    cwe=$(rules_sink_field CWE "$key")
    if [[ $OPT_MODE == conservative ]] && ((${AZ_SEV_RANK[$sev]-0} < 3)); then continue; fi
    kept+=("$e")
    r=$sev$'\t'$cwe$'\t'$f$'\t'$ln$'\t'$key$'\t'$b$'\t'$c$'\t'$p
    if [[ $f == "$OPT_SCRIPT" ]]; then main+=("$r"); else other+=("$r"); fi
  done
  AZ_EVENTS=("${kept[@]}")
  AZ_FINDINGS=("${main[@]}" "${other[@]}")
}

# report_count <SEV> -> cantidad de hallazgos de esa severidad
report_count() {
  local r n=0
  for r in "${AZ_FINDINGS[@]}"; do [[ ${r%%$'\t'*} == "$1" ]] && n=$((n + 1)); done
  printf '%d' "$n"
}

# report_exit_code: 1 solo en modo strict con al menos una alerta CRITICAL
report_exit_code() {
  if [[ $OPT_MODE == strict ]] && (($(report_count CRITICAL) > 0)); then return 1; fi
  return 0
}

# AZ_USE_COLOR se fija una vez en report_text (dentro de $(...) stdout nunca es un terminal)
AZ_USE_COLOR=0
_report_color() {
  ((AZ_USE_COLOR)) || return 0
  case $1 in
    CRITICAL) printf '\033[1;31m' ;;
    HIGH) printf '\033[31m' ;;
    MEDIUM) printf '\033[33m' ;;
    INFO) printf '\033[36m' ;;
    reset) printf '\033[0m' ;;
  esac
}

report_text() {
  local file=$1 e kind f ln a b c p r sev cwe key var cmd path code col rst s
  local -a src=() prop=() use=() un=() lines=()
  for e in "${AZ_EVENTS[@]}"; do
    kind=${e%%$'\t'*}
    case $kind in
      SOURCE) src+=("$e") ;;
      PROP) prop+=("$e") ;;
      USE) use+=("$e") ;;
      UNTAINT) un+=("$e") ;;
    esac
  done
  local lfile="" lines=()
  AZ_USE_COLOR=0
  [[ -t 1 && -z ${NO_COLOR-} ]] && AZ_USE_COLOR=1
  rst=$(_report_color reset)

  msgln title
  printf '%s: %s\n' "$(msg file)" "$file"
  msgln mode_dyn
  msgln script_rc "$MONITOR_RC"
  msgln alerts_found "${#AZ_FINDINGS[@]}"
  msgln excluded_lines "$AZ_EXCLUDED"
  if ((OPT_RECURSIVE)); then msgln files_analyzed "${#AZ_FILES[@]}" "$((${#AZ_FILES[@]} - 1))"; fi
  ((${#src[@]} == 0)) && { printf '\n'; msgln none; }
  if ((${#AZ_WARNINGS[@]})); then
    printf '\n%s\n' "$(msg hdr_warn)"
    for r in "${AZ_WARNINGS[@]}"; do
      IFS=$'\t' read -r f ln cmd path <<<"$r"
      printf '  ' ; msgln warn_unresolved "$path" "$f" "$ln"
    done
  fi

  if ((${#AZ_FINDINGS[@]})); then
    printf '\n%s\n' "$(msg hdr_alert)"
    for r in "${AZ_FINDINGS[@]}"; do
      IFS=$'\t' read -r sev cwe f ln key var cmd path <<<"$r"
      col=$(_report_color "$sev")
      printf '\n  %s[%s]%s %s:%s  %s (%s)\n' "$col" "$(msg "sev_$sev")" "$rst" "$f" "$ln" "$(rules_sink_label "$key")" "$cwe"
      if [[ $f != "$lfile" ]]; then
        lines=()
        [[ -r $f ]] && mapfile -t lines <"$f"
        lfile=$f
      fi
      code=${lines[ln - 1]-}
      code=${code#"${code%%[![:space:]]*}"}
      if ((AZ_USE_COLOR)); then   # linea del hallazgo resaltada (video inverso)
        printf '    %-16s \033[7m> %s\033[0m\n' "$(msg lbl_code):" "$code"
      else
        printf '    %-16s > %s\n' "$(msg lbl_code):" "$code"
      fi
      if [[ $key == CONSTANT ]]; then
        printf '    %-16s %s\n' "$(msg lbl_source):" "$(msg lbl_none)"
      else
        printf '    %-16s %s\n' "$(msg lbl_source):" "${path%% -> *}"
      fi
      printf '    %-16s %s\n' "$(msg lbl_sink):" "$cmd"
      printf '    %-16s %s\n' "$(msg lbl_ref):" "$cwe"
      if ((OPT_RECURSIVE)); then
        if [[ $f == "$OPT_SCRIPT" ]]; then s=origin_main; else s=origin_sec; fi
        printf '    %-16s %s\n' "$(msg lbl_origin):" "$(msg "$s")"
      fi
      printf '    %-16s %s\n' "$(msg lbl_expl):" "$(msg "expl_${key}")"
      case $key in
        EVAL|SUBSHELL|UNQUOTED|EXECCMD|SOURCEFILE|SSHCMD)
          printf '    %-16s %s\n' "$(msg lbl_recommendation):" "$(msg "rec_${key}")" ;;
      esac
      ((OPT_VERBOSE)) && printf '    %-16s %s\n' "$(msg lbl_path):" "$path"
    done
    printf '\n%s\n' "$(msg sev_summary)"
    for s in CRITICAL HIGH MEDIUM INFO; do
      (($(report_count "$s") > 0)) || continue
      printf '  %s%-12s%s %d\n' "$(_report_color "$s")" "$(msg "sev_$s")" "$rst" "$(report_count "$s")"
    done
  elif ((${#src[@]})); then
    printf '\n'
    msgln no_alerts
  fi

  if ((OPT_VERBOSE)); then
    ((${#src[@]})) && {
      printf '\n%s\n' "$(msg hdr_src)"
      for e in "${src[@]}"; do
        IFS=$'\t' read -r kind f ln a b c p <<<"$e"
        printf '  L%-4s %-22s %-22s -> %s\n' "$ln" "$(rules_type_label "$a")" "$b" "$c"
      done
    }
    if ((${#prop[@]})); then
      printf '\n%s\n' "$(msg hdr_prop)"
      for e in "${prop[@]}"; do
        IFS=$'\t' read -r kind f ln a b c p <<<"$e"
        printf '  L%-4s %-28s %s -> %s\n' "$ln" "$(rules_rule_label "$a")" "$b" "$c"
      done
    fi
    if ((${#use[@]})); then
      printf '\n%s\n' "$(msg hdr_use)"
      for e in "${use[@]}"; do
        IFS=$'\t' read -r kind f ln a b c p <<<"$e"
        printf '  L%-4s %-16s %-14s [%s]\n' "$ln" "$a" "$b" "$p"
      done
    fi
    if ((${#un[@]})); then
      printf '\n%s\n' "$(msg hdr_untaint)"
      for e in "${un[@]}"; do
        IFS=$'\t' read -r kind f ln a b c p <<<"$e"
        printf '  L%-4s %s (%s)\n' "$ln" "$b" "$(rules_rule_label "$a")"
      done
    fi
  fi
}

# ---- Exportacion JSON ----
_json_esc() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\t'/\\t}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//[[:cntrl:]]/ }
  printf '%s' "$s"
}

_json_path() {
  local p=$1 part out="[" first=1 more=1
  while ((more)); do
    if [[ $p == *' -> '* ]]; then part=${p%% -> *}; p=${p#* -> }; else part=$p; more=0; fi
    ((first)) || out+=", "
    first=0
    out+="\"$(_json_esc "$part")\""
  done
  printf '%s]' "$out"
}

# report_json <script>  -> imprime el JSON de la sesion
report_json() {
  local file=$1 r sev cwe f ln key var cmd path src n=0 total=${#AZ_FINDINGS[@]} s first=1
  printf '{\n'
  printf '  "file": "%s",\n' "$(_json_esc "$file")"
  printf '  "mode": "%s",\n' "$OPT_MODE"
  printf '  "script_exit_status": %d,\n' "$MONITOR_RC"
  printf '  "excluded_lines": %d,\n' "$AZ_EXCLUDED"
  printf '  "files_analyzed": ['
  for r in "${AZ_FILES[@]}"; do
    ((first)) || printf ', '
    first=0
    printf '"%s"' "$(_json_esc "$r")"
  done
  first=1
  printf '],\n  "warnings": ['
  for r in "${AZ_WARNINGS[@]}"; do
    IFS=$'\t' read -r f ln cmd path <<<"$r"
    ((first)) || printf ', '
    first=0
    printf '{"file": "%s", "line": %d, "command": "%s", "target": "%s", "type": "UNRESOLVED"}' \
      "$(_json_esc "$f")" "$ln" "$(_json_esc "$cmd")" "$(_json_esc "$path")"
  done
  first=1
  printf '],\n'
  printf '  "summary": {'
  for s in CRITICAL HIGH MEDIUM INFO; do
    ((first)) || printf ', '
    first=0
    printf '"%s": %d' "$s" "$(report_count "$s")"
  done
  printf '},\n  "findings": ['
  for r in "${AZ_FINDINGS[@]}"; do
    IFS=$'\t' read -r sev cwe f ln key var cmd path <<<"$r"
    n=$((n + 1))
    src=${path%% -> *}
    [[ $key == CONSTANT ]] && src=""
    printf '\n    {\n'
    printf '      "file": "%s",\n' "$(_json_esc "$f")"
    printf '      "line": %d,\n' "$ln"
    if [[ $f == "$file" ]]; then printf '      "origin": "main",\n'; else printf '      "origin": "secondary",\n'; fi
    printf '      "severity": "%s",\n' "$sev"
    printf '      "confidence": "CONFIRMED",\n'
    printf '      "analysis": "dynamic",\n'
    printf '      "source": "%s",\n' "$(_json_esc "$src")"
    printf '      "path": %s,\n' "$(_json_path "$path")"
    printf '      "sink": "%s",\n' "$(_json_esc "$cmd")"
    printf '      "type": "%s",\n' "$key"
    printf '      "cwe": "%s",\n' "$cwe"
    printf '      "explanation": "%s"\n' "$(_json_esc "$(msg "expl_${key}")")"
    printf '    }'
    ((n < total)) && printf ','
  done
  ((total)) && printf '\n  '
  printf ']\n}\n'
}

# report_export <script>  -> escribe OPT_EXPORT_FILE; un error no interrumpe el analisis
report_export() {
  [[ -n $OPT_EXPORT_FILE ]] || return 0
  if { report_json "$1" >"$OPT_EXPORT_FILE"; } 2>/dev/null; then
    ((OPT_QUIET)) || msgln export_ok "$OPT_EXPORT_FILE" >&2
  else
    _err err_export "$OPT_EXPORT_FILE"
  fi
  return 0
}
