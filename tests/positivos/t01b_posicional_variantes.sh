#!/bin/bash
todos="$@"
valor="${2:-defecto}"
for arg in "$@"; do
  echo "$arg"
done
echo "$0"
