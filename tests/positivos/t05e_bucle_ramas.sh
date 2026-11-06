#!/bin/bash
# ANALYZER-ARGS: uno dos
ejecutar() { :; }
for item in "$@"; do
  ejecutar "$item"
done
if [ -n "$1" ]; then
  r="$1-ok"
else
  r="vacio"
fi
ejecutar "$r"
