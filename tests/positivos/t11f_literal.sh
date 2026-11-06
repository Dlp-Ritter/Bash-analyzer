#!/bin/bash
# ANALYZER-ARGS: ls
[[ $1 == "ls" ]] || exit 1
eval "$1"
