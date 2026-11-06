#!/bin/bash
# ANALYZER-ARGS: dato
# ANALYZER-OPTS: --mode=conservative
entrada="$(printf '%q' "$1")"
eval "echo $entrada"
cmd="ls"
eval "$cmd"
