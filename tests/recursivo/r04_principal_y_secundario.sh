#!/bin/bash
# ANALYZER-ARGS: true
# ANALYZER-OPTS: -r
eval "$1"
source ./tests/recursivo/sec_eval.sh "$1"
