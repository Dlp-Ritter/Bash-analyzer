#!/bin/bash
# ANALYZER-ARGS: abc
# ANALYZER-OPTS: --mode=conservative
[[ $1 =~ ^[a-z]+$ ]] || exit 1
eval "$1"
