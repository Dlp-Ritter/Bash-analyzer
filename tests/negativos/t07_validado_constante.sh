#!/bin/bash
# ANALYZER-ARGS: dato
entrada="$(printf '%q' "$1")"
eval "echo $entrada"
cmd="ls"
eval "$cmd"
