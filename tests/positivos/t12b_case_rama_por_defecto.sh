#!/bin/bash
# ANALYZER-ARGS: zzz
case "$1" in
  start|stop)
    ;;
  *)
    echo "valor no reconocido"
    ;;
esac
eval "$1"
