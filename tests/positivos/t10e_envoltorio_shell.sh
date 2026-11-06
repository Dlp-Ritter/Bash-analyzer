#!/bin/bash
# ANALYZER-ARGS: true
sudo() { :; }
sudo bash -c "$1"
env FOO=1 bash -c "$1"
