#!/bin/bash
# ANALYZER-ARGS: abc
case "$1" in
  [a-z]*)
    ;;
  *)
    exit 1
    ;;
esac
eval "$1"
