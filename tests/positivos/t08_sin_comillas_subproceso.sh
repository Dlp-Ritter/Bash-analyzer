#!/bin/bash
# ANALYZER-ARGS: nada.txt
archivo=$1
rm $archivo
bash -c "$1"
