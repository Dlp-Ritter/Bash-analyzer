#!/bin/bash
# ANALYZER-ARGS: start
case $1 in
  start|stop)
    eval "$1"
    ;;
  *)
    exit 1
    ;;
esac
