#!/usr/bin/env bash
# install.sh - instala (o desinstala) el analizador. Local: no usa la red.
#   ./install.sh [--prefix=DIR]     instala dist/analyzer en DIR/bin (por defecto ~/.local, o /usr/local si es root)
#   ./install.sh --uninstall [--prefix=DIR]
set -eu
cd "$(dirname "$0")"
prefix=${HOME:-.}/.local
[[ $(id -u) -eq 0 ]] && prefix=/usr/local
action=install
for a in "$@"; do
  case $a in
    --prefix=*) prefix=${a#*=} ;;
    --uninstall) action=uninstall ;;
    -h | --help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "Opcion desconocida: $a" >&2; exit 2 ;;
  esac
done
dest=$prefix/bin/analyzer
if [[ $action == uninstall ]]; then
  rm -f -- "$dest"
  echo "Desinstalado: $dest"
  exit 0
fi
./build.sh >/dev/null
mkdir -p -- "$prefix/bin"
cp -- dist/analyzer "$dest"
chmod 755 -- "$dest"
echo "Instalado: $dest"
case ":$PATH:" in *":$prefix/bin:"*) ;; *) echo "Aviso: $prefix/bin no esta en el PATH." ;; esac
