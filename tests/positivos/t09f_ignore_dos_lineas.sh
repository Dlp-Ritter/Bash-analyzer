#!/bin/bash
# ANALYZER-ARGS: true
# ignore-rule
eval "$1"
bash -c "$1" # ignore-rule:SUBSHELL
