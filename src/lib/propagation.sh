# propagation.sh - Motor de propagacion dinamico (Iteracion 2)
#
# Se ejecuta DENTRO del proceso del script analizado, desde el trap DEBUG que
# instala el monitor. Por cada comando realmente ejecutado:
#   1. detecta fuentes externas (Iteracion 1, en modo dinamico),
#   2. propaga el estado "tainted" a las variables que reciben el dato,
#   3. registra los usos (comando que recibe una variable contaminada),
#   4. elimina la marca cuando la variable se sobrescribe con otro valor.
#
# Cada evento se escribe como una linea TSV en el descriptor AZ_FD:
#   tipo <TAB> archivo <TAB> linea <TAB> a <TAB> b <TAB> c <TAB> ruta
#
#   SOURCE   a=tipo de fuente   b=referencia      c=variable
#   PROP     a=regla            b=origen          c=destino
#   USE      a=comando          b=variable usada  c=-
#   UNTAINT  a=OVERWRITE        b=variable        c=-
#
# Limitaciones conocidas: las variables se identifican solo por nombre (sin
# distinguir ambitos de funciones) y los parametros posicionales dentro de
# funciones se siguen unicamente cuando la funcion se invoca con un dato
# contaminado como argumento.

declare -gA AZ_TAINT=() AZ_FRAME=() AZ_SANITIZED=()
AZ_MODE=strict   # strict | conservative (lo fija el monitor)
AZ_HARMLESS=' echo printf '   # conservative: no alerta variable sin comillas en estos comandos
AZ_EMITTED=$'\n'
AZ_PENDING_CALL=""
AZ_PENDING_VALID=""   # validacion por lista blanca por resolver: <negada>|<clave>
AZ_FD=""
AZ_RULE=""
AZ_CMD=""
AZ_CMD_IDX=-1
AZ_WORDS=()

AZ_RE_HEREDOC='<<-?[[:space:]]*([^[:space:]<])'
AZ_RE_SANITIZE='(\$\(|`)[[:space:]]*printf[[:space:]]+[^)`]*%q'
AZ_RE_FUNCDEF='^[[:space:]]*(function[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)'
AZ_RE_PLAIN_REF='^[[:space:]]*"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?[[:space:]]*$'
AZ_RE_ASSIGN_WORD='^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?='
AZ_RE_POSIDX='^\$\{?([0-9]+)'
# Comandos que no se consideran "uso" de un dato (condiciones, declaraciones, E/S de variables)
AZ_NON_USE=' [[ [ test (( local declare typeset readonly export for case select read mapfile readarray unset shift set return exit true false : '

# _az_emit <clave-de-duplicado> <tipo> <archivo> <linea> <a> <b> <c> <ruta>
_az_emit() {
  local key=$1 rec
  shift
  [[ $AZ_EMITTED == *$'\n'"$key"$'\n'* ]] && return 0
  AZ_EMITTED+="$key"$'\n'
  printf -v rec '%s\t%s\t%s\t%s\t%s\t%s\t%s' "$@"
  printf '%s\n' "$rec" >&"$AZ_FD"
}

# Divide una linea en palabras respetando comillas y $( ... ) -> AZ_WORDS
_az_words() {
  local s=$1 ch cur="" prev="" i n=${#1} dq=0 sq=0 par=0 bt=0 inw=0
  AZ_WORDS=()
  for ((i = 0; i < n; i++)); do
    ch=${s:i:1}
    if ((sq)); then
      cur+=$ch
      inw=1
      [[ $ch == "'" ]] && sq=0
      prev=$ch
      continue
    fi
    case $ch in
      "'") ((dq)) || sq=1; cur+=$ch; inw=1 ;;
      '"') dq=$((1 - dq)); cur+=$ch; inw=1 ;;
      '`') ((dq)) || bt=$((1 - bt)); cur+=$ch; inw=1 ;;
      '(') if [[ $prev == '$' ]] || ((par)); then par=$((par + 1)); fi; cur+=$ch; inw=1 ;;
      ')') ((par)) && par=$((par - 1)); cur+=$ch; inw=1 ;;
      *)
        if [[ $ch == [[:space:]] ]] && ((!dq && !par && !bt)); then
          if ((inw)); then AZ_WORDS+=("$cur"); cur=""; inw=0; fi
        else
          cur+=$ch
          inw=1
        fi
        ;;
    esac
    prev=$ch
  done
  ((inw)) && AZ_WORDS+=("$cur")
  return 0
}

# Localiza el comando (primera palabra que no es asignacion) -> AZ_CMD, AZ_CMD_IDX
_az_find_cmd() {
  local i w
  AZ_CMD=""
  AZ_CMD_IDX=-1
  for ((i = 0; i < ${#AZ_WORDS[@]}; i++)); do
    w=${AZ_WORDS[i]}
    [[ $w =~ $AZ_RE_ASSIGN_WORD ]] && continue
    [[ $w == '!' ]] && continue
    AZ_CMD=${w//[\"\']/}
    AZ_CMD_IDX=$i
    return 0
  done
  return 0
}

# Clasifica la regla de propagacion de una linea de asignacion -> AZ_RULE
_az_rule() {
  local line=$1 rhs
  if [[ $line =~ $AZ_RE_FOR ]]; then
    AZ_RULE=FOR
    return 0
  fi
  rhs=${line#*=}
  if [[ $rhs =~ $AZ_RE_PLAIN_REF ]]; then
    AZ_RULE=ASSIGN
  elif [[ $rhs == *'$('* || $rhs == *'`'* ]]; then
    AZ_RULE=CMDSUB
  else
    AZ_RULE=INTERP
  fi
}

# Agrega una referencia al arreglo del llamador (_rk, _rn, _rp), sin repetir.
# tipo: V = variable contaminada, S = fuente directa ($1, $HOME...), P = parametro de funcion
_az_addref() {
  local i
  for ((i = 0; i < ${#_rk[@]}; i++)); do
    [[ ${_rk[i]}${_rn[i]} == "$1$2" ]] && return 0
  done
  _rk+=("$1")
  _rn+=("$2")
  _rp+=("$3")
}

# _az_collect_refs <texto> <profundidad>  -> llena _rk/_rn/_rp del llamador
_az_collect_refs() {
  local rest=$1 depth=$2 name ref idx key k
  while [[ $rest =~ $AZ_RE_VAR ]]; do
    name=${BASH_REMATCH[1]}
    rest=${rest#*"${BASH_REMATCH[0]}"}
    if [[ -n ${AZ_TAINT[$name]+x} ]]; then
      _az_addref V "$name" "${AZ_TAINT[$name]}"
    elif [[ -n ${AZ_INITIAL_ENV[$name]-} && -z ${AZ_ASSIGNED[$name]-} && -z ${AZ_SPECIAL_VARS[$name]-} &&
      $name != BASH_* && $name != COMP_* && $name != _ ]]; then
      _az_addref S "\$$name" "\$$name"
    fi
  done
  rest=$1
  while [[ $rest =~ $AZ_RE_POS ]]; do
    ref=${BASH_REMATCH[0]}
    rest=${rest#*"$ref"}
    if ((depth == 0)); then
      _az_addref S "$ref" "$ref"
    elif [[ $ref =~ $AZ_RE_POSIDX ]]; then
      idx=${BASH_REMATCH[1]}
      key=".p$depth.$idx"
      [[ -n ${AZ_TAINT[$key]+x} ]] && _az_addref P "$ref" "${AZ_TAINT[$key]}"
    else
      for k in ${AZ_FRAME[$depth]-}; do
        key=".p$depth.$k"
        _az_addref P "$ref" "${AZ_TAINT[$key]}"
        break
      done
    fi
  done
  return 0
}

# Llamada a una funcion: los argumentos contaminados pasan a ser parametros
# contaminados de la funcion (profundidad d+1). Usa AZ_WORDS y AZ_CMD_IDX.
_az_map_call() {
  local fname=$1 d=$2 nd i k idx=0 w path
  local -a _rk _rn _rp
  nd=$((d + 1))
  for k in ${AZ_FRAME[$nd]-}; do unset "AZ_TAINT[.p$nd.$k]"; done
  AZ_FRAME[$nd]=""
  for ((i = AZ_CMD_IDX + 1; i < ${#AZ_WORDS[@]}; i++)); do
    w=${AZ_WORDS[i]}
    [[ $w == [0-9]*'>'* || $w == '>'* || $w == '<'* ]] && continue
    idx=$((idx + 1))
    _rk=() _rn=() _rp=()
    _az_collect_refs "$w" "$d"
    if ((${#_rk[@]})); then
      path="${_rp[0]} -> $fname:\$$idx"
      AZ_TAINT[".p$nd.$idx"]=$path
      AZ_FRAME[$nd]+="$idx "
      _az_emit "PROP|$file|$ln|ARGPARAM|$fname|$idx" PROP "$file" "$ln" ARGPARAM "${_rn[0]}" "$fname:\$$idx" "$path"
    fi
  done
}

# ---- Validacion por lista blanca (Iteracion 6) ----
# Reconoce [[ $x =~ ^<regex-acotada>$ ]] y [[ $x == "literal" ]] (y sus negaciones) como validacion.
# El resultado del [[ ]] se lee en el comando siguiente ($? previo): si el valor encajo en la
# lista blanca, la variable queda marcada como saneada (AZ_SANITIZED).

# _az_whitelist_regex <regex>: 0 si es una lista blanca estricta (acotada, sin comodines ni
# clases que admitan metacaracteres del shell).
_az_whitelist_regex() {
  local re=$1 st br inner brre='\[\^?\]?(\[:[a-z]+:\]|[^]\[])*\]'
  [[ $re == '^'* && $re == *'$' ]] || return 1
  st=$re
  while [[ $st =~ $brre ]]; do
    br=${BASH_REMATCH[0]}
    [[ $br == '[^'* ]] && return 1
    inner=${br#[}
    inner=${inner%]}
    inner=${inner//\[:alnum:\]/}
    inner=${inner//\[:alpha:\]/}
    inner=${inner//\[:digit:\]/}
    inner=${inner//\[:upper:\]/}
    inner=${inner//\[:lower:\]/}
    inner=${inner//\[:xdigit:\]/}
    [[ $inner =~ ^[A-Za-z0-9_.@:,+=%/-]*$ ]] || return 1
    st=${st/"$br"/_}
  done
  st=${st//\\./_}
  [[ $st == *'.'* || $st == *'\'* ]] && return 1
  [[ $st =~ ^\^[A-Za-z0-9_/@:,=%+*?{}()|-]*\$$ ]]
}

# _az_val_key <nombre> <profundidad>: clave de AZ_TAINT/AZ_SANITIZED de la variable validada
# (nombre, $N a profundidad 0 o $VAR de entorno); 1 si no es un dato rastreado.
_az_val_key() {
  local name=$1 depth=$2
  if [[ $name == [0-9]* ]]; then
    ((depth == 0)) && [[ $name != 0 ]] || return 1
    AZ_V_KEY="\$$name"
  elif [[ -n ${AZ_TAINT[$name]+x} ]]; then
    AZ_V_KEY=$name
  elif [[ -n ${AZ_INITIAL_ENV[$name]-} && -z ${AZ_ASSIGNED[$name]-} ]]; then
    AZ_V_KEY="\$$name"
  else
    return 1
  fi
}

# _az_case_alt_safe <alternativa>: 0 si el patron de case es un literal (o clases acotadas),
# sin * ni ? (un patron como [a-z]* admite cualquier cola y NO es lista blanca).
_az_case_alt_safe() {
  local a=$1
  if [[ $a == \"*\" || $a == \'*\' ]]; then a=${a:1:${#a}-2}; [[ $a == *[\$\`\\\"\']* ]] && return 1; fi
  [[ -n $a ]] || return 1
  [[ $a =~ ^([A-Za-z0-9_.@:,+=%/-]|\[[A-Za-z0-9_-]+\]|\[\[:(alnum|alpha|digit|upper|lower|xdigit):\]\])+$ ]]
}

# _az_parse_case <texto> <archivo> <linea> <profundidad>
# case "$x" in a|b) ... ;; *) exit 1 ;; esac  ->  lista blanca. Como Bash no expone la rama
# elegida, se lee el bloque del archivo y se decide con el SIGUIENTE comando ejecutado: si su
# linea cae en una rama de patrones seguros (o despues de esac, cuando todas las ramas son
# seguras y la rama * tiene cuerpo), la variable queda saneada. Solo bloques multilinea.
AZ_CASE_KEY="" AZ_CASE_FILE="" AZ_CASE_END=0 AZ_CASE_AFTER_OK=0
AZ_CASE_SAFE=()
_az_parse_case() {
  local t=$1 file=$2 ln=$3 depth=$4 name i n l alt rest body
  local -a L=() starts=() safes=() isdef=() bodies=()
  AZ_CASE_KEY=""
  AZ_CASE_SAFE=()
  [[ $t =~ ^[[:space:]]*case[[:space:]]+\"?\$\{?([A-Za-z_][A-Za-z0-9_]*|[0-9]+)\}?\"?[[:space:]]+in[[:space:]]*$ ]] || return 1
  name=${BASH_REMATCH[1]}
  _az_val_key "$name" "$depth" || return 1
  [[ -r $file ]] || return 1
  mapfile -t L <"$file"
  n=${#L[@]}
  local end=0 re_alt='^[[:space:]]*\(?[[:space:]]*([]A-Za-z0-9_.@:,+=%/*?|"'\'' [-]+)\)(.*)$'
  for ((i = ln; i < n; i++)); do   # i = indice de la linea siguiente a la del case
    l=${L[i]}
    if [[ $l =~ ^[[:space:]]*esac([[:space:];]|$) ]]; then end=$((i + 1)); break; fi
    [[ $l =~ ^[[:space:]]*case[[:space:]] ]] && return 1          # case anidado: no se interpreta
    [[ $l == *';&'* || $l == *';;&'* ]] && return 1
    if [[ $l =~ $re_alt ]]; then
      alt=${BASH_REMATCH[1]}
      rest=${BASH_REMATCH[2]}
      starts+=("$((i + 1))")
      bodies+=("$rest")
      local ok=1 df=0 a
      IFS='|' read -ra _alts <<<"$alt"
      for a in "${_alts[@]}"; do
        a=${a#"${a%%[![:space:]]*}"}; a=${a%"${a##*[![:space:]]}"}
        if [[ $a == '*' ]]; then df=1; ok=0; else _az_case_alt_safe "$a" || ok=0; fi
      done
      safes+=("$ok"); isdef+=("$df")
    elif ((${#starts[@]})); then
      bodies[${#bodies[@]} - 1]+=" $l"
    fi
  done
  ((end > ln + 0 && ${#starts[@]})) || return 1
  local all_safe=1 def_body=0
  for ((i = 0; i < ${#starts[@]}; i++)); do
    if ((isdef[i])); then
      body=${bodies[i]//;;/ }; body=${body%%#*}
      [[ $body =~ [^[:space:]] ]] && def_body=1
    elif ((!safes[i])); then all_safe=0; fi
    if ((safes[i])); then
      local e=$((end - 1))
      ((i + 1 < ${#starts[@]})) && e=$((starts[i + 1] - 1))
      AZ_CASE_SAFE+=("${starts[i]}-$e")
    fi
  done
  AZ_CASE_KEY=$AZ_V_KEY
  AZ_CASE_FILE=$file
  AZ_CASE_END=$end
  AZ_CASE_AFTER_OK=$((all_safe && def_body))
  return 0
}

# _az_parse_validation <texto> <profundidad>  -> AZ_V_NEG y AZ_V_KEY; 1 si no es una validacion
_az_parse_validation() {
  local t=$1 depth=$2 neg=0 name op pat key inner
  [[ $t =~ ^[[:space:]]*\[\[[[:space:]]+(.*)[[:space:]]+\]\][[:space:]]*$ ]] || return 1
  t=${BASH_REMATCH[1]}
  if [[ $t == '!'[[:space:]]* ]]; then
    neg=1
    t=${t#!}
    t=${t#"${t%%[![:space:]]*}"}
  fi
  [[ $t == *'&&'* || $t == *'||'* ]] && return 1
  [[ $t =~ ^\"?\$\{?([A-Za-z_][A-Za-z0-9_]*|[0-9]+)\}?\"?[[:space:]]+(=~|==|=|!=)[[:space:]]+(.+)$ ]] || return 1
  name=${BASH_REMATCH[1]}
  op=${BASH_REMATCH[2]}
  pat=${BASH_REMATCH[3]}
  _az_val_key "$name" "$depth" || return 1
  key=$AZ_V_KEY
  case $op in
    '=~')
      [[ $pat == [\"\']* ]] && return 1
      _az_whitelist_regex "$pat" || return 1
      ;;
    *)
      if [[ $pat == \"*\" || $pat == \'*\' ]]; then
        inner=${pat:1:${#pat}-2}
        [[ $inner == *[\$\`\\]* ]] && return 1
      else
        [[ $pat == *[\*\?\[\$\`\(\)\|\&\;\<\>\"\'\\]* ]] && return 1
      fi
      [[ $op == '!=' ]] && neg=$((1 - neg))
      ;;
  esac
  AZ_V_NEG=$neg
  AZ_V_KEY=$key
  return 0
}

# _az_prop_process <archivo> <linea> <comando> <profundidad> <estado-del-comando-previo>
_az_prop_process() {
  local file=$1 ln=$2 cmd=$3 depth=$4 pstatus=${5-1}
  local line seenlist=$'\n' r f2 l2 type ref var st t i p newpath old has_prop=0 found
  local -a _rk=() _rn=() _rp=() _tg=()
  local -A proped=() seeded=()

  # Resultado del [[ ]] de lista blanca anterior: $? del comando previo (0 = verdadero)
  if [[ -n $AZ_PENDING_VALID ]]; then
    local pv=$AZ_PENDING_VALID
    AZ_PENDING_VALID=""
    if { ((pstatus == 0)) && [[ ${pv%%|*} == 0 ]]; } || { ((pstatus == 1)) && [[ ${pv%%|*} == 1 ]]; }; then
      AZ_SANITIZED[${pv#*|}]=1
    fi
  fi

  # case como lista blanca: la rama ejecutada se deduce de la linea de este comando
  if [[ -n $AZ_CASE_KEY ]]; then
    local ck=$AZ_CASE_KEY rg
    AZ_CASE_KEY=""
    if [[ $file == "$AZ_CASE_FILE" ]]; then
      if ((ln > AZ_CASE_END)); then
        ((AZ_CASE_AFTER_OK)) && AZ_SANITIZED[$ck]=1
      else
        for rg in "${AZ_CASE_SAFE[@]}"; do
          if ((ln >= ${rg%-*} && ln <= ${rg#*-})); then AZ_SANITIZED[$ck]=1; fi
        done
      fi
    fi
  fi

  # BASH_COMMAND incluye el cuerpo de los heredocs: con delimitador entrecomillado
  # no se expande nada (se descarta); sin comillas se conserva (puede expandir datos).
  local text=$cmd
  if [[ $cmd == *$'\n'* && $cmd =~ $AZ_RE_HEREDOC ]]; then
    case ${BASH_REMATCH[1]} in
      \"* | \'* | \\*) text=${cmd%%$'\n'*} ;;
    esac
  fi
  text=${text//$'\n'/ }
  if _az_parse_validation "$text" "$depth"; then AZ_PENDING_VALID="$AZ_V_NEG|$AZ_V_KEY"; fi
  _az_parse_case "$text" "$file" "$ln" "$depth" || true
  _az_clean_line "$text"
  line=$AZ_CLEANED
  [[ $line =~ [^[:space:]] ]] || return 0

  # Bash dispara el trap dos veces al entrar a una funcion (llamada y entrada): se omite la entrada.
  if [[ -n $AZ_PENDING_CALL ]]; then
    if [[ $AZ_PENDING_CALL == "$depth|$cmd" ]]; then
      AZ_PENDING_CALL=""
      return 0
    fi
    AZ_PENDING_CALL=""
  fi
  [[ $line =~ $AZ_RE_FUNCDEF ]] && return 0

  AZ_SCAN_MODE=dynamic
  AZ_DEPTH=$depth
  AZ_SOURCES=()
  AZ_REDIR_FILE=0
  _az_scan_target "$line"
  _az_scan_positional "$line"
  _az_scan_env "$line"
  _az_scan_files "$line"
  _az_scan_stdin "$line"
  _az_scan_commands "$line"
  _az_collect_refs "$line" "$depth"
  [[ -n $AZ_LINE_TARGET ]] && IFS=',' read -ra _tg <<<"$AZ_LINE_TARGET"

  # --- Propagacion hacia las variables destino ---
  for ((i = 0; i < ${#_rk[@]}; i++)); do [[ ${_rk[i]} != S ]] && has_prop=1; done
  if ((${#_tg[@]})); then
    if ((has_prop)); then
      _az_rule "$line"
      for t in "${_tg[@]}"; do
        for ((i = 0; i < ${#_rk[@]}; i++)); do
          [[ ${_rk[i]} == S ]] && continue
          newpath="${_rp[i]} -> $t"
          if [[ ${_rp[i]} == "$t" || ${_rp[i]} == *" -> $t" ]]; then newpath=${_rp[i]}; fi
          _az_emit "PROP|$file|$ln|$AZ_RULE|${_rn[i]}|$t" PROP "$file" "$ln" "$AZ_RULE" "${_rn[i]}" "$t" "$newpath"
          if [[ -z ${proped[$t]-} ]]; then
            AZ_TAINT[$t]=$newpath
            proped[$t]=1
          fi
        done
      done
    elif ((${#AZ_SOURCES[@]} == 0 && AZ_LINE_READ == 0)); then
      # sobrescritura con un valor que no esta contaminado
      for t in "${_tg[@]}"; do
        [[ -n ${AZ_TAINT[$t]+x} ]] || continue
        [[ $line == *"$t+="* ]] && continue
        old=${AZ_TAINT[$t]}
        unset "AZ_TAINT[$t]"
        _az_emit "UNTAINT|$file|$ln|$t" UNTAINT "$file" "$ln" OVERWRITE "$t" - "$old"
      done
    fi
  fi

  # --- Fuentes detectadas en esta linea ---
  for r in "${AZ_SOURCES[@]}"; do
    IFS=$'\t' read -r f2 l2 type ref var st <<<"$r"
    p=$ref
    [[ $var != - ]] && p="$ref -> $var"
    _az_emit "SOURCE|$f2|$l2|$type|$ref" SOURCE "$f2" "$l2" "$type" "$ref" "$var" "$p"
    if [[ $var != - ]]; then
      for t in ${var//,/ }; do
        if [[ -z ${proped[$t]-} && -z ${seeded[$t]-} ]]; then
          AZ_TAINT[$t]="$ref -> $t"
          seeded[$t]=1
        fi
      done
    fi
  done

  # --- Saneamiento: printf %q o dato ya validado por lista blanca (propagado desde sus referencias) ---
  local san
  san=0
  if [[ $text =~ $AZ_RE_SANITIZE ]]; then
    san=1
  elif ((${#_rk[@]})); then
    san=1
    for ((i = 0; i < ${#_rk[@]}; i++)); do
      if [[ ${_rk[i]} == P || -z ${AZ_SANITIZED[${_rn[i]}]-} ]]; then san=0; fi
    done
    # una fuente de la linea que no sea una de las referencias (p. ej. $(cat f)) rompe la cadena
    for r in "${AZ_SOURCES[@]}"; do
      IFS=$'\t' read -r f2 l2 type ref var st <<<"$r"
      found=0
      for ((i = 0; i < ${#_rk[@]}; i++)); do [[ ${_rk[i]} == S && ${_rn[i]} == "$ref" ]] && found=1; done
      ((found)) || san=0
    done
  fi
  for t in "${_tg[@]}"; do
    if [[ -z ${AZ_TAINT[$t]+x} ]]; then unset "AZ_SANITIZED[$t]"; continue; fi
    if ((san)); then AZ_SANITIZED[$t]=1; else unset "AZ_SANITIZED[$t]"; fi
  done

  # --- Usos y llamadas a funciones ---
  _az_words "$line"
  _az_find_cmd
  if ((AZ_CMD_IDX >= 0)); then
    if [[ $AZ_NON_USE != *" $AZ_CMD "* ]]; then
      for ((i = 0; i < ${#_rk[@]}; i++)); do
        _az_emit "USE|$file|$ln|$AZ_CMD|${_rn[i]}" USE "$file" "$ln" "$AZ_CMD" "${_rn[i]}" - "${_rp[i]} -> $AZ_CMD"
      done
    fi
    _az_sink_check "$AZ_CMD" "$depth"
    _az_check_invocation "$AZ_CMD"
    if declare -F -- "$AZ_CMD" >/dev/null 2>&1; then
      _az_map_call "$AZ_CMD" "$depth"
      AZ_PENDING_CALL="$((depth + 1))|$cmd"
    fi
  fi

  _az_mark_assigned "$line"
  return 0
}

# _az_alert <sink> <indice> <cmd>   (usa _rk/_rn/_rp, file, ln del llamador)
# Sufijos del sink: /SAN (dato saneado con printf %q) y /LOW (comando de salida
# inofensivo). El modo strict/conservative filtra despues, en report.sh.
_az_alert() {
  local sink=$1 n=$2 base=${3##*/}
  if [[ ${_rk[n]} != P && -n ${AZ_SANITIZED[${_rn[n]}]-} ]]; then
    sink+=/SAN
  elif [[ $sink == UNQUOTED && $AZ_HARMLESS == *" $base "* ]]; then
    sink+=/LOW
  fi
  _az_emit "ALERT|$file|$ln|$sink|${_rn[n]}|$3" ALERT "$file" "$ln" "$sink" "${_rn[n]}" "$3" "${_rp[n]} -> $3"
}

# Envoltorios que ejecutan otro comando: devuelve en AZ_EFF_IDX el indice (en AZ_WORDS)
# del comando envuelto, saltando opciones, asignaciones VAR=valor y duraciones.
# _az_wrapped_index <envoltorio> <indice-inicial>
_az_wrapped_index() {
  local b=$1 i=$2 w skipnext=0 first=1
  AZ_EFF_IDX=-1
  for ((; i < ${#AZ_WORDS[@]}; i++)); do
    w=${AZ_WORDS[i]}
    if ((skipnext)); then skipnext=0; continue; fi
    if [[ $w == [0-9]*[\<\>]* || $w == [\<\>]* ]]; then continue; fi
    [[ $w == -- ]] && continue
    if [[ $w == -* ]]; then
      case $b$w in
        sudo-[ughpCDRTU] | xargs-[IndELsaP] | env-[uCS] | nice-n | timeout-[sk] | exec-a) skipnext=1 ;;
      esac
      continue
    fi
    if [[ ($b == env || $b == sudo) && $w =~ $AZ_RE_ASSIGN_WORD ]]; then continue; fi
    if [[ $b == timeout && $first -eq 1 ]]; then first=0; continue; fi
    AZ_EFF_IDX=$i
    return 0
  done
  return 1
}

# Puntos sensibles: eval, subproceso "<shell> -c", variable sin comillas (Iteracion 3) y
# ejecucion indirecta: comando controlado por el dato ($cmd, sudo/exec/xargs/env... $cmd),
# source/. con ruta controlada y comando remoto de ssh (ampliacion).
# Usa AZ_WORDS y AZ_CMD_IDX; <depth> es la profundidad de funciones.
_az_sink_check() {
  local cmd=$1 depth=$2 i n w prev="" stripped sink seen_c=0 base=${1##*/} rest nm
  local eff=$AZ_CMD_IDX effbase skipnext=0 nonopt=0 effword
  local -a _rk _rn _rp

  # Comando cuyo nombre viene del dato: $cmd args
  _rk=() _rn=() _rp=()
  _az_collect_refs "${AZ_WORDS[AZ_CMD_IDX]}" "$depth"
  for ((n = 0; n < ${#_rk[@]}; n++)); do _az_alert EXECCMD "$n" "${AZ_WORDS[AZ_CMD_IDX]}"; done

  [[ $AZ_NON_USE == *" $cmd "* ]] && return 0

  # Envoltorios: el comando efectivo es el que ejecutan
  case $base in
    sudo | doas | exec | xargs | env | nohup | nice | timeout | command | builtin | time)
      if _az_wrapped_index "$base" "$((AZ_CMD_IDX + 1))"; then
        eff=$AZ_EFF_IDX
        effword=${AZ_WORDS[eff]}
        _rk=() _rn=() _rp=()
        _az_collect_refs "$effword" "$depth"
        for ((n = 0; n < ${#_rk[@]}; n++)); do _az_alert EXECCMD "$n" "$base $effword"; done
      fi
      ;;
  esac
  effbase=${AZ_WORDS[eff]//[\"\']/}
  effbase=${effbase##*/}

  for ((i = AZ_CMD_IDX + 1; i < ${#AZ_WORDS[@]}; i++)); do
    w=${AZ_WORDS[i]}
    # redirecciones: el destino no es un argumento del comando
    if [[ $w == [0-9]*[\<\>]* || $w == [\<\>]* || $prev =~ ^[0-9]*[\<\>]+$ ]]; then prev=$w; continue; fi
    prev=$w
    ((i == eff && eff != AZ_CMD_IDX)) && continue   # el comando envuelto ya se reviso arriba
    sink=""
    if ((i > eff)); then
      case $effbase in
        eval) sink=EVAL ;;
        bash | sh | dash | ksh | zsh)
          if [[ $w =~ ^-[A-Za-z]*c[A-Za-z]*$ ]]; then seen_c=1; continue; fi
          ((seen_c)) && sink=SUBSHELL
          ;;
        source | .)
          ((i == eff + 1)) && sink=SOURCEFILE
          ;;
        ssh)
          # opciones con argumento propio; luego host y, a partir de ahi, el comando remoto
          if ((skipnext)); then skipnext=0; continue; fi
          if [[ $w == -* ]]; then
            case $w in -[bcDEeFIiJLlmOopQRSWw]) skipnext=1 ;; esac
            continue
          fi
          nonopt=$((nonopt + 1))
          ((nonopt >= 2)) && sink=SSHCMD
          ;;
      esac
    fi
    _rk=() _rn=() _rp=()
    if [[ -n $sink ]]; then
      _az_collect_refs "$w" "$depth"
    else
      stripped=$w
      while [[ $stripped =~ \"[^\"]*\" ]]; do stripped=${stripped/"${BASH_REMATCH[0]}"/}; done
      [[ $stripped == *'$'* ]] || continue
      sink=UNQUOTED
      _az_collect_refs "$stripped" "$depth"
    fi
    for ((n = 0; n < ${#_rk[@]}; n++)); do _az_alert "$sink" "$n" "$cmd"; done
    # Informativa: variable sin comillas que no contiene datos externos
    if [[ $sink == UNQUOTED ]]; then
      rest=$stripped
      while [[ $rest =~ $AZ_RE_VAR ]]; do
        nm=${BASH_REMATCH[1]}
        rest=${rest#*"${BASH_REMATCH[0]}"}
        if [[ -z ${AZ_TAINT[$nm]+x} && -n ${AZ_ASSIGNED[$nm]-} ]]; then
          _az_emit "ALERT|$file|$ln|UNQUOTED/CONST|$nm|$cmd" ALERT "$file" "$ln" UNQUOTED/CONST "$nm" "$cmd" "$nm -> $cmd"
        fi
      done
    fi
  done
  return 0
}

# Con -r: avisa si se invoca un script secundario con ruta literal que no existe
# (source, ".", <shell> script, ./script). Las rutas con variables o sustituciones
# no se resuelven aqui: el monitor analiza lo que realmente se ejecuta.
_az_check_invocation() {
  local cmd=$1 i w base=${1##*/} target=""
  ((AZ_RECURSIVE)) || return 0
  case $base in
    source | .)
      target=${AZ_WORDS[AZ_CMD_IDX + 1]-}
      ;;
    bash | sh | dash | ksh | zsh)
      for ((i = AZ_CMD_IDX + 1; i < ${#AZ_WORDS[@]}; i++)); do
        w=${AZ_WORDS[i]}
        [[ $w =~ ^-[A-Za-z]*c[A-Za-z]*$ ]] && return 0
        [[ $w == -* || $w == [\<\>]* || $w == [0-9]*[\<\>]* ]] && continue
        target=$w
        break
      done
      ;;
    *)
      [[ $cmd == */* ]] && target=$cmd
      ;;
  esac
  [[ -n $target ]] || return 0
  target=${target//[\"\']/}
  [[ $target == *[\$\`\*\?\[]* || $target == '~'* ]] && return 0
  [[ -f $target ]] && return 0
  if [[ $target != */* && ( $base == source || $base == . ) ]] && type -P -- "$target" >/dev/null 2>&1; then
    return 0
  fi
  _az_emit "UNRESOLVED|$file|$ln|$cmd|$target" UNRESOLVED "$file" "$ln" "$cmd" "$target" - -
  return 0
}

# ---- Salidas del analisis dinamico ----
propagation_report_tsv() {
  local e
  for e in "${AZ_EVENTS[@]}"; do printf '%s\n' "$e"; done
}
