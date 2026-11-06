#!/bin/bash
x="abc123"
[[ $x =~ ^([a-z]+)([0-9]+)$ ]]
echo "letras=${BASH_REMATCH[1]} numeros=${BASH_REMATCH[2]}"
echo intermedio
echo "letras=${BASH_REMATCH[1]}"
