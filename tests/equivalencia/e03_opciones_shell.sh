#!/bin/bash
set -euo pipefail
IFS=$'\n'
f() { local a="${1:-vacio}"; echo "f:$a"; }
f
f "x y"
arr=(uno dos)
echo "${arr[*]}"
false || true
echo "fin"
