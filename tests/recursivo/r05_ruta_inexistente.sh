#!/bin/bash
# ANALYZER-ARGS: true
# ANALYZER-OPTS: -r
source ./tests/recursivo/no_existe.sh
echo "continua"
eval "$1"
