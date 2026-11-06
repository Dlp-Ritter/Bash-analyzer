#!/bin/bash
# ANALYZER-ARGS: start
case "$1" in
  start|stop)
    ;;
  *)
    exit 1
    ;;
esac
eval "$1"
