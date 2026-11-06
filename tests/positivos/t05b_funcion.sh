#!/bin/bash
# ANALYZER-ARGS: dato
procesar() {
  local x="$1"
  ejecutar "$x"
}
ejecutar() { :; }
a="$1"
procesar "$a"
