#!/bin/bash
# ANALYZER-ARGS: abc
[[ $1 =~ ^[a-z]+$ ]] || exit 1
x="$1"
eval "$x"
