#!/bin/bash
# ANALYZER-ARGS: true
sudo() { :; }
sudo "$1"
xargs "$1" </dev/null
exec "$1"
