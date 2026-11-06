#!/bin/bash
# ANALYZER-ARGS: abc
[[ ! $1 =~ ^[a-z0-9_]+$ ]] && exit 1
eval "$1"
