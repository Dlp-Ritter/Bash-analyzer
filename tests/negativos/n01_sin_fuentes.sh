#!/bin/bash
# $1 y $USER_INPUT dentro de un comentario no cuentan
x='$1 $HOME $(date)'
y="valor"
echo "escapado: \$1 \$(date)"
echo "$x $y"
cat <<'FIN'
$1 $USER_INPUT $(date) read -r z
FIN
if (( y < 3 )); then echo ok; fi
