# rules.sh - carga del catalogo de reglas (desacoplado del motor, RNF-05)

declare -gA AZ_SPECIAL_VARS=() TYPE_DESC_ES=() TYPE_DESC_EN=() RULE_DESC_ES=() RULE_DESC_EN=() SINK_DESC_ES=() SINK_DESC_EN=() AZ_SINK_SEV=() AZ_SINK_CWE=()

# Devuelve el contenido del catalogo: desde rules/sources.conf o, en la
# version empaquetada, desde la copia embebida por build.sh.
_rules_content() {
  local dir=${ANALYZER_RULES_DIR:-${ANALYZER_ROOT:+$ANALYZER_ROOT/../rules}}
  if [[ -n $dir && -r $dir/sources.conf ]]; then
    cat -- "$dir/sources.conf"
  elif declare -F _embedded_sources_conf >/dev/null; then
    _embedded_sources_conf
  else
    return 1
  fi
}

rules_load() {
  local content line key val v v1 v2 v3 v4
  content=$(_rules_content) || return 1
  while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] && continue
    key=${line%%=*}
    val=${line#*=}
    case $key in
      SPECIAL_VARS)
        for v in $val; do AZ_SPECIAL_VARS[$v]=1; done
        ;;
      TYPE_*)
        TYPE_DESC_ES[${key#TYPE_}]=${val%%|*}
        TYPE_DESC_EN[${key#TYPE_}]=${val#*|}
        ;;
      SINK_*)
        # SINK_<K>=severidad|CWE|descripcion es|descripcion en
        IFS='|' read -r v1 v2 v3 v4 <<<"$val"
        AZ_SINK_SEV[${key#SINK_}]=$v1
        AZ_SINK_CWE[${key#SINK_}]=$v2
        SINK_DESC_ES[${key#SINK_}]=$v3
        SINK_DESC_EN[${key#SINK_}]=$v4
        ;;
      RULE_*)
        RULE_DESC_ES[${key#RULE_}]=${val%%|*}
        RULE_DESC_EN[${key#RULE_}]=${val#*|}
        ;;
    esac
  done <<<"$content"
  return 0
}

# rules_type_label <TIPO>
rules_type_label() {
  if [[ $ANALYZER_LANG == en ]]; then
    printf '%s' "${TYPE_DESC_EN[$1]-$1}"
  else
    printf '%s' "${TYPE_DESC_ES[$1]-$1}"
  fi
}

# rules_rule_label <REGLA>
rules_rule_label() {
  if [[ $ANALYZER_LANG == en ]]; then
    printf '%s' "${RULE_DESC_EN[$1]-$1}"
  else
    printf '%s' "${RULE_DESC_ES[$1]-$1}"
  fi
}

# rules_sink_label <SINK>
rules_sink_label() {
  if [[ $ANALYZER_LANG == en ]]; then
    printf '%s' "${SINK_DESC_EN[$1]-$1}"
  else
    printf '%s' "${SINK_DESC_ES[$1]-$1}"
  fi
}

# rules_sink_field SEV|CWE <SINK>
rules_sink_field() {
  case $1 in
    SEV) printf '%s' "${AZ_SINK_SEV[$2]-MEDIUM}" ;;
    CWE) printf '%s' "${AZ_SINK_CWE[$2]-CWE-78}" ;;
  esac
}
