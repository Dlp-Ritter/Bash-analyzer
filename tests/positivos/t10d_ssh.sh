#!/bin/bash
# ANALYZER-ARGS: uptime
ssh() { :; }
ssh -p 22 servidor "$1"
