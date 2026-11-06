#!/bin/bash
# ANALYZER-ARGS: abc
[[ $1 =~ ^.*$ ]] || exit 1
eval "$1"
