#!/bin/bash
echo hola mundo >/dev/null
echo "ultimo_arg=$_"
ls /no_existe_zz 2>/dev/null
echo "rc=$?"
false | true
echo "pipe=${PIPESTATUS[*]}"
