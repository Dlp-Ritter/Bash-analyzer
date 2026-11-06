#!/bin/bash
# ANALYZER-ARGS: /etc/hostname
archivo="$1"
contenido=$(cat "$archivo")
resultado="[$contenido]"
ejecutar() { :; }
ejecutar "$resultado"
