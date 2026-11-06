#!/bin/bash
# ANALYZER-ARGS: start
# ANALYZER-OPTS: --mode=conservative
case "$1" in
  start|stop)
    ;;
  *)
    exit 1
    ;;
esac
eval "$1"
