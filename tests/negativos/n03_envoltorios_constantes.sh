#!/bin/bash
# ANALYZER-ARGS: dato
sudo() { :; }
ssh() { :; }
sudo ls
cmd="ls"
$cmd
source /dev/null
ssh servidor uptime
ssh "$1" uptime
echo "$1" | xargs echo
env FOO=1 true
