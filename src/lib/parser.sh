# parser.sh - lectura del script y limpieza por linea
#
# Limpia cada linea para que el detector no se confunda con texto que no se
# ejecuta: elimina comentarios, vacia el contenido de comillas simples y las
# secuencias escapadas, y omite el cuerpo de los heredocs.
# Limitaciones conocidas (Iteracion 1): no sigue comillas que abarcan varias
# lineas ni construcciones anidadas muy complejas.

AZ_CLEANED=""

# _az_clean_line <linea>  -> deja el resultado en AZ_CLEANED
_az_clean_line() {
  local line=$1 out="" ch prev="" sq=0 dq=0 i n=${#1}
  for ((i = 0; i < n; i++)); do
    ch=${line:i:1}
    if ((sq)); then
      if [[ $ch == "'" ]]; then
        sq=0
        out+="'"
      else
        out+=" "
      fi
      prev=$ch
      continue
    fi
    if [[ $ch == '\' ]]; then
      out+="  "
      ((i++))
      prev=" "
      continue
    fi
    if [[ $ch == "'" && $dq -eq 0 ]]; then
      sq=1
      out+="'"
      prev=$ch
      continue
    fi
    if [[ $ch == '"' ]]; then
      dq=$((1 - dq))
      out+='"'
      prev=$ch
      continue
    fi
    if [[ $ch == '#' && $dq -eq 0 && ( -z $prev || $prev == [[:space:]] ) ]]; then
      break
    fi
    out+=$ch
    prev=$ch
  done
  AZ_CLEANED=$out
}

# parser_walk <archivo> <callback>
# Llama a <callback> <archivo> <n.linea> <linea_limpia> por cada linea de
# codigo (sin vacias, sin comentarios y sin cuerpos de heredoc). Las lineas
# que terminan en "\" se unen con la siguiente y se reportan con el numero de
# la primera.
parser_walk() {
  local file=$1 cb=$2
  local raw acc="" acc_ln=0 ln=0 hd_tag="" hd_dash=0 cmp
  local re_hd='<<(-?)[[:space:]]*["'\'']?([A-Za-z_][A-Za-z0-9_]*)'
  local pre

  while IFS= read -r raw || [[ -n $raw ]]; do
    ln=$((ln + 1))
    raw=${raw%$'\r'}

    if [[ -n $hd_tag ]]; then
      cmp=$raw
      ((hd_dash)) && cmp=${raw#"${raw%%[!$'\t']*}"}
      [[ $cmp == "$hd_tag" ]] && hd_tag=""
      continue
    fi

    if [[ -z $acc ]]; then acc_ln=$ln; fi
    if [[ $raw == *'\' && ${raw: -2} != '\\' ]]; then
      acc+="${raw%\\} "
      continue
    fi
    acc+=$raw

    # Heredoc: se detecta sobre la linea cruda (el terminador puede ir entre comillas)
    pre=$acc
    while [[ $pre =~ $re_hd ]]; do
      # descarta "<<<" (here-string): el caracter anterior no puede ser "<"
      local before=${pre%%"${BASH_REMATCH[0]}"*}
      if [[ ${before: -1} != '<' ]]; then
        hd_dash=0
        [[ ${BASH_REMATCH[1]} == "-" ]] && hd_dash=1
        hd_tag=${BASH_REMATCH[2]}
        break
      fi
      pre=${pre#*"${BASH_REMATCH[0]}"}
    done

    _az_clean_line "$acc"
    if [[ $AZ_CLEANED =~ [^[:space:]] ]]; then
      "$cb" "$file" "$acc_ln" "$AZ_CLEANED"
    fi
    acc=""
  done <"$file"

  # continuacion pendiente al final del archivo
  if [[ -n $acc ]]; then
    _az_clean_line "$acc"
    if [[ $AZ_CLEANED =~ [^[:space:]] ]]; then
      "$cb" "$file" "$acc_ln" "$AZ_CLEANED"
    fi
  fi
}
