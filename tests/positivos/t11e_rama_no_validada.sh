#!/bin/bash
# ANALYZER-ARGS: ABC1
if [[ $1 =~ ^[a-z]+$ ]]; then
  echo ok
else
  eval "$1"
fi
