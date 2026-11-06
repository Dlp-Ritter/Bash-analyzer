# sources.sh - Detector de Fuentes (Iteracion 1)
#
# Identifica las cinco categorias de fuentes externas definidas en la
# Iteracion 1 y deja un registro por cada una en el arreglo AZ_SOURCES:
#
#   archivo <TAB> linea <TAB> tipo <TAB> referencia <TAB> variable <TAB> estado
#
# tipo:  POSITIONAL | ENV | FILE | STDIN | COMMAND
# estado: siempre TAINTED en esta iteracion. La Iteracion 2 consume este
# registro para propagar el estado a otras variables.

AZ_SOURCES=()
declare -gA AZ_ASSIGNED=()
AZ_LINE_TARGET=""
AZ_LINE_READ=0
AZ_LINE_READ_STDIN=1
AZ_REDIR_FILE=0
AZ_SCAN_MODE=static   # static | dynamic (lo fija el monitor)
AZ_DEPTH=0            # profundidad de funciones (solo modo dinamico)
declare -gA AZ_INITIAL_ENV=()

# ---- Expresiones regulares (ERE de Bash) ----
AZ_RE_POS='\$(\{([1-9][0-9]*|[@*])[^}]*\}|[1-9]|[@*])'
AZ_RE_VAR='\$\{?([A-Za-z_][A-Za-z0-9_]*)'
AZ_RE_PRINTENV='(^|[;&|(`{])[[:space:]]*printenv([[:space:]]+([A-Za-z_][A-Za-z0-9_]*))?'
AZ_RE_CAT_FILE='(^|[;&|(`{])[[:space:]]*((then|do|else)[[:space:]]+)?cat[[:space:]]+(-[A-Za-z]+[[:space:]]+)*([^[:space:];|&)<>-][^[:space:];|&)<>]*)'
AZ_RE_CAT_STDIN='(^|[;&|(`{])[[:space:]]*cat([[:space:]]+-)?[[:space:]]*([;|&)]|$)'
AZ_RE_REDIR='(^|[^<])<[[:space:]]*([^<(&=[:space:];|)][^[:space:];|&)]*)'
AZ_RE_ARITH='\(\([^()]*\)\)'
AZ_RE_DBRACKET='\[\[[^]]*\]\]'
AZ_RE_CMDSUB='\$\(([^()]*)\)'
AZ_RE_BACKTICK='`([^`]*)`'
AZ_RE_FOR='^[[:space:]]*for[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+in([[:space:]]|$)'
AZ_RE_ASSIGN='(^|[;&|({]|[[:space:]](then|do|else)[[:space:]])[[:space:]]*((export|local|declare|typeset|readonly)([[:space:]]+-[A-Za-z]+)*[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)(\[[^]]*\])?\+?=([^=]|$)'
AZ_RE_ASSIGN_ANY='(^|[[:space:];&|({])([A-Za-z_][A-Za-z0-9_]*)(\[[^]]*\])?\+?=([^=]|$)'
AZ_RE_DECL='(^|[;&|({])[[:space:]]*(local|declare|typeset|readonly|export)[[:space:]]+([^;|&)]*)'
AZ_RE_READ='(^|[;&|(`{])[[:space:]]*((then|do|else|while|until|if|!)[[:space:]]+)*read([[:space:]]+([^;|&)<>]*))?([;|&)<>]|$)'
AZ_RE_MAPFILE='(^|[;&|(`{])[[:space:]]*((then|do|else|while|until|if|!)[[:space:]]+)*(mapfile|readarray)([[:space:]]+([^;|&)<>]*))?([;|&)<>]|$)'

_az_trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

# _az_src_add <TIPO> <referencia>   (usa file, ln y seenlist del llamador)
_az_src_add() {
  local type=$1 ref=$2 key
  key=$'\n'"$type|$ref"$'\n'
  [[ $seenlist == *"$key"* ]] && return 0
  seenlist+="$type|$ref"$'\n'
  AZ_SOURCES+=("$file"$'\t'"$ln"$'\t'"$type"$'\t'"$ref"$'\t'"${AZ_LINE_TARGET:--}"$'\t'"TAINTED")
}

# Variable(s) que reciben el dato en la linea (asignacion, for, read, mapfile)
_az_scan_target() {
  local line=$1 args w pending stdin=1 t
  local -a words=() targets=()
  AZ_LINE_TARGET=""
  AZ_LINE_READ=0
  AZ_LINE_READ_STDIN=1

  if [[ $line =~ $AZ_RE_FOR ]]; then
    AZ_LINE_TARGET=${BASH_REMATCH[1]}
    return 0
  fi
  if [[ $line =~ $AZ_RE_ASSIGN ]]; then
    AZ_LINE_TARGET=${BASH_REMATCH[6]}
  fi

  if [[ $line =~ $AZ_RE_READ ]]; then
    args=${BASH_REMATCH[5]}
    AZ_LINE_READ=1
    read -ra words <<<"$args"
    pending=""
    for w in "${words[@]}"; do
      if [[ -n $pending ]]; then
        case $pending in
          a) targets+=("$w") ;;
          u) [[ $w != 0 ]] && stdin=0 ;;
        esac
        pending=""
        continue
      fi
      case $w in
        -*[pnNtdi]) pending=x ;;
        -*u) pending=u ;;
        -*a) pending=a ;;
        -*) ;;
        *) [[ $w =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && targets+=("$w") ;;
      esac
    done
    AZ_LINE_READ_STDIN=$stdin
    ((${#targets[@]})) || targets=(REPLY)
    printf -v t '%s,' "${targets[@]}"
    AZ_LINE_TARGET=${t%,}
  elif [[ $line =~ $AZ_RE_MAPFILE ]]; then
    args=${BASH_REMATCH[6]}
    AZ_LINE_READ=2
    read -ra words <<<"$args"
    pending=""
    for w in "${words[@]}"; do
      if [[ -n $pending ]]; then
        [[ $pending == u && $w != 0 ]] && stdin=0
        pending=""
        continue
      fi
      case $w in
        -*[dnOsCc]) pending=x ;;
        -*u) pending=u ;;
        -*) ;;
        *) [[ $w =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && targets=("$w") ;;
      esac
    done
    AZ_LINE_READ_STDIN=$stdin
    ((${#targets[@]})) || targets=(MAPFILE)
    AZ_LINE_TARGET=${targets[0]}
  fi
}

_az_scan_positional() {
  local rest=$1 ref
  while [[ $rest =~ $AZ_RE_POS ]]; do
    ref=${BASH_REMATCH[0]}
    rest=${rest#*"$ref"}
    # En modo dinamico, dentro de una funcion los $N son parametros de la
    # funcion (no argumentos del script): los maneja el motor de propagacion.
    if [[ ${AZ_SCAN_MODE-static} == dynamic ]] && ((AZ_DEPTH > 0)); then continue; fi
    _az_src_add POSITIONAL "$ref"
  done
}

_az_scan_env() {
  local rest=$1 name
  while [[ $rest =~ $AZ_RE_VAR ]]; do
    name=${BASH_REMATCH[1]}
    rest=${rest#*"${BASH_REMATCH[0]}"}
    [[ -n ${AZ_ASSIGNED[$name]-} || -n ${AZ_SPECIAL_VARS[$name]-} ]] && continue
    [[ $name == BASH_* || $name == COMP_* || $name == _ ]] && continue
    # En modo dinamico solo cuenta lo que realmente venia en el entorno.
    if [[ ${AZ_SCAN_MODE-static} == dynamic && -z ${AZ_INITIAL_ENV[$name]-} ]]; then continue; fi
    _az_src_add ENV "\$$name"
  done
  rest=$1
  if [[ $rest =~ $AZ_RE_PRINTENV ]]; then
    name=${BASH_REMATCH[3]}
    _az_src_add ENV "printenv${name:+ $name}"
  fi
}

_az_scan_files() {
  local rest=$1 arg redir_line m
  # cat <archivo>
  while [[ $rest =~ $AZ_RE_CAT_FILE ]]; do
    m=${BASH_REMATCH[0]}
    arg=${BASH_REMATCH[5]}
    arg=${arg//\"/}
    arg=${arg//\'/}
    rest=${rest#*"$m"}
    if [[ $arg == /dev/stdin ]]; then
      _az_src_add STDIN "cat /dev/stdin"
    else
      _az_src_add FILE "cat $arg"
    fi
  done
  # redireccion de entrada (< archivo); se ignoran ((...)) y [[ ... ]]
  redir_line=$1
  while [[ $redir_line =~ $AZ_RE_ARITH ]]; do redir_line=${redir_line/"${BASH_REMATCH[0]}"/ }; done
  while [[ $redir_line =~ $AZ_RE_DBRACKET ]]; do redir_line=${redir_line/"${BASH_REMATCH[0]}"/ }; done
  rest=$redir_line
  while [[ $rest =~ $AZ_RE_REDIR ]]; do
    m=${BASH_REMATCH[0]}
    arg=${BASH_REMATCH[2]}
    arg=${arg//\"/}
    arg=${arg//\'/}
    rest=${rest#*"$m"}
    if [[ $arg == /dev/stdin ]]; then
      _az_src_add STDIN "< /dev/stdin"
    else
      _az_src_add FILE "< $arg"
      AZ_REDIR_FILE=1
    fi
  done
}

_az_scan_stdin() {
  local line=$1
  if ((AZ_LINE_READ == 1 && AZ_LINE_READ_STDIN && !AZ_REDIR_FILE)); then
    _az_src_add STDIN "read"
  elif ((AZ_LINE_READ == 2 && AZ_LINE_READ_STDIN && !AZ_REDIR_FILE)); then
    _az_src_add STDIN "mapfile"
  fi
  if ((!AZ_REDIR_FILE)) && [[ $line =~ $AZ_RE_CAT_STDIN ]]; then
    _az_src_add STDIN "cat"
  fi
}

# true si el contenido de una sustitucion ya se clasifico como archivo/stdin/entorno
_az_cmdsub_is_other() {
  local inner=$1
  [[ $inner =~ $AZ_RE_CAT_FILE ]] && return 0
  [[ $inner =~ $AZ_RE_CAT_STDIN ]] && return 0
  [[ $inner =~ $AZ_RE_PRINTENV ]] && return 0
  [[ $inner =~ ^[[:space:]]*\< ]] && return 0
  return 1
}

_az_scan_commands() {
  local w=$1 whole inner
  while [[ $w =~ $AZ_RE_CMDSUB ]]; do
    whole=${BASH_REMATCH[0]}
    inner=${BASH_REMATCH[1]}
    w=${w/"$whole"/__SUB__}
    _az_cmdsub_is_other "$inner" && continue
    inner=$(_az_trim "${inner//__SUB__/...}")
    _az_src_add COMMAND "\$($inner)"
  done
  w=$1
  while [[ $w =~ $AZ_RE_BACKTICK ]]; do
    whole=${BASH_REMATCH[0]}
    inner=${BASH_REMATCH[1]}
    w=${w/"$whole"/__SUB__}
    _az_cmdsub_is_other "$inner" && continue
    inner=$(_az_trim "$inner")
    _az_src_add COMMAND "\`$inner\`"
  done
}

# Registra las variables asignadas en la linea (despues de analizar sus usos)
_az_mark_assigned() {
  local line=$1 rest name w t
  local -a words
  rest=$line
  while [[ $rest =~ $AZ_RE_ASSIGN_ANY ]]; do
    name=${BASH_REMATCH[2]}
    AZ_ASSIGNED[$name]=1
    rest=${rest#*"${BASH_REMATCH[0]}"}
  done
  rest=$line
  while [[ $rest =~ $AZ_RE_DECL ]]; do
    read -ra words <<<"${BASH_REMATCH[3]}"
    rest=${rest#*"${BASH_REMATCH[0]}"}
    for w in "${words[@]}"; do
      [[ $w == -* ]] && continue
      name=${w%%=*}
      [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && AZ_ASSIGNED[$name]=1
    done
  done
  if [[ -n $AZ_LINE_TARGET ]]; then
    IFS=',' read -ra words <<<"$AZ_LINE_TARGET"
    for t in "${words[@]}"; do AZ_ASSIGNED[$t]=1; done
  fi
}

# sources_scan_line <archivo> <n.linea> <linea_limpia>   (callback de parser_walk)
sources_scan_line() {
  local file=$1 ln=$2 line=$3
  local seenlist=$'\n'
  AZ_REDIR_FILE=0
  _az_scan_target "$line"
  _az_scan_positional "$line"
  _az_scan_env "$line"
  _az_scan_files "$line"
  _az_scan_stdin "$line"
  _az_scan_commands "$line"
  _az_mark_assigned "$line"
}

# ---- Indicadores heurísticos del modo estático ----
# El modo estático no intenta sustituir al monitor dinámico ni a ShellCheck:
# identifica sinks potenciales y una relación léxica sencilla con fuentes.
# Formato: archivo TAB línea TAB clave TAB variable TAB comando TAB ruta
AZ_STATIC_FINDINGS=()
declare -gA AZ_STATIC_TAINT=()

_az_static_ref_tainted() {
  local line=$1 rest name ref
  [[ $line =~ \$\{?([1-9][0-9]*|[@*])\}? ]] && return 0
  rest=$line
  while [[ $rest =~ \$\{?([A-Za-z_][A-Za-z0-9_]*) ]]; do
    name=${BASH_REMATCH[1]}
    [[ -n ${AZ_STATIC_TAINT[$name]-} ]] && return 0
    rest=${rest#*"${BASH_REMATCH[0]}"}
  done
  return 1
}

_az_static_tainted_name() {
  local line=$1 rest name
  if [[ $line =~ \$\{?([1-9][0-9]*|[@*])\}? ]]; then
    printf '%s' "${BASH_REMATCH[0]}"
    return 0
  fi
  rest=$line
  while [[ $rest =~ \$\{?([A-Za-z_][A-Za-z0-9_]*) ]]; do
    name=${BASH_REMATCH[1]}
    if [[ -n ${AZ_STATIC_TAINT[$name]-} ]]; then
      printf '$%s' "$name"
      return 0
    fi
    rest=${rest#*"${BASH_REMATCH[0]}"}
  done
  return 1
}

_az_static_add() {
  local file=$1 ln=$2 key=$3 var=$4 cmd=$5 path=$6 item
  item="$file"$'\t'"$ln"$'\t'"$key"$'\t'"$var"$'\t'"$cmd"$'\t'"$path"
  for item in "${AZ_STATIC_FINDINGS[@]}"; do
    [[ $item == "$file"$'\t'"$ln"$'\t'"$key"$'\t'* ]] && return 0
  done
  AZ_STATIC_FINDINGS+=("$file"$'\t'"$ln"$'\t'"$key"$'\t'"$var"$'\t'"$cmd"$'\t'"$path")
}

_az_static_scan_line() {
  local file=$1 ln=$2 line=$3 var="" path="" target
  _az_scan_target "$line"
  if _az_static_ref_tainted "$line"; then
    var=$(_az_static_tainted_name "$line")
    path="$var"
    [[ -n $AZ_LINE_TARGET ]] && AZ_STATIC_TAINT[$AZ_LINE_TARGET]=1
  fi
  # Las fuentes detectadas por el escáner también alimentan la propagación
  # estática, incluso cuando la asignación no contiene una referencia simple.
  if [[ -n $AZ_LINE_TARGET ]]; then
    local src
    for src in "${AZ_SOURCES[@]}"; do
      [[ $src == "$file"$'\t'"$ln"$'\t'* ]] && AZ_STATIC_TAINT[$AZ_LINE_TARGET]=1
    done
  fi
  _az_static_ref_tainted "$line" || return 0
  var=${var:-$(_az_static_tainted_name "$line")}
  path=${path:-$var}

  if [[ $line =~ (^|[[:space:];|])eval([[:space:]]|$) ]]; then
    _az_static_add "$file" "$ln" EVAL "$var" "eval" "$path -> eval"
  elif [[ $line =~ (^|[[:space:];|])(bash|sh)([[:space:]]+[^[:space:]]*)?[[:space:]]+-c([[:space:]]|$) ]]; then
    _az_static_add "$file" "$ln" SUBSHELL "$var" "${BASH_REMATCH[2]} -c" "$path -> ${BASH_REMATCH[2]} -c"
  elif [[ $line =~ (^|[[:space:];|])(source|\.)[[:space:]] ]]; then
    _az_static_add "$file" "$ln" SOURCEFILE "$var" "${BASH_REMATCH[2]}" "$path -> ${BASH_REMATCH[2]}"
  elif [[ $line =~ (^|[[:space:];|])ssh[[:space:]] ]]; then
    _az_static_add "$file" "$ln" SSHCMD "$var" "ssh" "$path -> ssh"
  elif [[ $line =~ (^|[[:space:];|])(sudo|exec|xargs|env)[[:space:]] ]]; then
    _az_static_add "$file" "$ln" EXECCMD "$var" "${BASH_REMATCH[2]}" "$path -> ${BASH_REMATCH[2]}"
  elif [[ $line =~ ^[[:space:]]*\$[A-Za-z_][A-Za-z0-9_]*([[:space:]]|$) ]]; then
    _az_static_add "$file" "$ln" EXECCMD "$var" "$var" "$path -> comando"
  elif [[ $line =~ (^|[[:space:]])\$\{?[A-Za-z_][A-Za-z0-9_]*\}?([[:space:]]|$) ]]; then
    _az_static_add "$file" "$ln" UNQUOTED "$var" "variable sin comillas" "$path -> uso sin comillas"
  fi
}

_az_static_trap_warning=0
_az_static_scan_trap() {
  [[ $3 =~ trap[[:space:]]+(-[[:space:]]+DEBUG|:\'?[[:space:]]+DEBUG) ]] && _az_static_trap_warning=1
}

# sources_detect <archivo>  -> llena AZ_SOURCES y los indicadores estáticos
sources_detect() {
  AZ_SOURCES=()
  AZ_STATIC_FINDINGS=()
  AZ_STATIC_TAINT=()
  AZ_ASSIGNED=()
  _az_static_trap_warning=0
  parser_walk "$1" sources_scan_line
  # Segundo recorrido: las fuentes ya identificadas permiten relacionar
  # asignaciones y sinks en orden de aparición sin ejecutar el script.
  AZ_STATIC_TAINT=()
  parser_walk "$1" _az_static_scan_line
  parser_walk "$1" _az_static_scan_trap
}

# ---- Salidas ----
sources_report_tsv() {
  local r
  for r in "${AZ_SOURCES[@]}"; do printf '%s\n' "$r"; done
}

sources_report_text() {
  local file=$1 r f ln type ref var st label key cmd path sev cwe
  local -A count=()
  local -a order=()
  msgln title
  printf '%s: %s\n' "$(msg file)" "$file"
  msgln mode_static
  msgln found "${#AZ_SOURCES[@]}"
  if ((${#AZ_SOURCES[@]} == 0)); then
    msgln none
  else
    printf '\n'
    for r in "${AZ_SOURCES[@]}"; do
      IFS=$'\t' read -r f ln type ref var st <<<"$r"
      label=$(rules_type_label "$type")
      printf '  L%-4s %-22s %-22s -> %s [%s]\n' "$ln" "$label" "$ref" "$var" "$st"
      [[ -z ${count[$type]-} ]] && order+=("$type")
      count[$type]=$((${count[$type]-0} + 1))
    done
    printf '\n'
    msgln summary
    for type in "${order[@]}"; do
      printf '  %s: %d\n' "$(rules_type_label "$type")" "${count[$type]}"
    done
  fi

  if ((${#AZ_STATIC_FINDINGS[@]})); then
    printf '\n%s\n' "$(msg hdr_static)"
    for r in "${AZ_STATIC_FINDINGS[@]}"; do
      IFS=$'\t' read -r f ln key var cmd path <<<"$r"
      sev=$(rules_sink_field SEV "$key")
      cwe=$(rules_sink_field CWE "$key")
      printf '  [%s] %s:%s  %s (%s)\n' "$(msg "sev_$sev")" "$f" "$ln" "$(rules_sink_label "$key")" "$cwe"
      printf '    %-16s %s\n' "$(msg lbl_source):" "${var:--}"
      printf '    %-16s %s\n' "$(msg lbl_sink):" "$cmd"
      printf '    %-16s %s\n' "$(msg lbl_path):" "$path"
      printf '    %-16s %s\n' "$(msg lbl_confidence):" "$(msg static_confidence)"
    done
    printf '%s\n' "$(msg static_note)"
  fi
  if (( _az_static_trap_warning )); then
    printf '\n%s\n' "$(msg warn_debug_trap)"
  fi
}
