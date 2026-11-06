#!/bin/bash
read -r primera < config.txt
mapfile -t lineas
datos=$(< entrada.txt)
