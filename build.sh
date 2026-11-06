#!/usr/bin/env bash
# build.sh - genera dist/analyzer, un unico archivo sin dependencias externas
# (RNF-03). Incluye los modulos de src/lib y una copia del catalogo de reglas.
set -eu
cd "$(dirname "$0")"
out=dist/analyzer
mkdir -p dist
{
  printf '#!/usr/bin/env bash\n'
  printf '# Generado por build.sh - no editar a mano.\n'
  cat <<'__GUARD__'
# Requiere Bash 4.4 o superior / Requires Bash 4.4 or newer.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
  printf 'analyzer: se requiere Bash 4.4 o superior (version actual: %s) / Bash 4.4+ required.\n' "$BASH_VERSION" >&2
  exit 2
fi
__GUARD__
  for lib in i18n rules log parser sources propagation monitor report cli; do
    printf '\n# ===== %s =====\n' "$lib"
    cat "src/lib/$lib.sh"
  done
  printf '\n# ===== catalogo de reglas embebido =====\n'
  printf '_embedded_sources_conf() {\n  cat <<'"'"'__RULES__'"'"'\n'
  cat rules/sources.conf
  printf '__RULES__\n}\n\n'
  printf '\n# ===== manual de usuario embebido =====\n'
  printf '_embedded_manual() {\n  cat <<'"'"'__MANUAL__'"'"'\n'
  cat 'docs/manual de usuario.txt'
  printf '__MANUAL__\n}\n\n'
  printf 'analyzer_main "$@"\n'
} >"$out"
chmod +x "$out"
echo "Generado: $out"
