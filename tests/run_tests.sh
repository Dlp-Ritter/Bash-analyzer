#!/usr/bin/env bash
# run_tests.sh - ejecuta las pruebas del laboratorio.
# Ejecutar SOLO dentro del entorno aislado (VM o contenedor).
#   ./tests/run_tests.sh              prueba src/analyzer
#   ANALYZER=dist/analyzer ./tests/run_tests.sh   prueba la version empaquetada
cd "$(dirname "$0")/.." || exit 1
ANALYZER=${ANALYZER:-src/analyzer}
# Las pruebas dinamicas son deliberadas y se ejecutan dentro del laboratorio.
export ANALYZER_ALLOW_EXECUTION=1
export ANALYZER_LOG_DIR
ANALYZER_LOG_DIR=$(mktemp -d)
pass=0 fail=0 skip=0

ok()   { pass=$((pass + 1)); printf 'PASS  %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }

# --- Pruebas de deteccion de fuentes (comparan contra tests/expected/*.tsv) ---
for f in tests/positivos/*.sh tests/negativos/*.sh; do
  name=$(basename "$f" .sh)
  exp="tests/expected/$name.tsv"
  if [[ ! -f $exp ]]; then
    skip=$((skip + 1)); printf 'SKIP  %s (sin resultado esperado en esta iteracion)\n' "$name"
    continue
  fi
  got=$("$ANALYZER" --static --format=tsv "$f" 2>&1)
  if [[ $got == "$(<"$exp")" ]]; then ok "$name"; else
    bad "$name"
    diff <(printf '%s\n' "$got") "$exp" | sed 's/^/      /'
  fi
done

# --- Indicadores heurísticos del modo estático ---
static_eval=$($ANALYZER --static tests/positivos/t06_eval.sh true 2>&1)
static_unquoted=$($ANALYZER --static tests/positivos/t08_sin_comillas_subproceso.sh true 2>&1)
if [[ $static_eval == *"Indicadores estaticos:"* && $static_eval == *"CWE-78"* &&
      $static_unquoted == *"CWE-88"* && $static_unquoted == *"CWE-78"* &&
      $static_eval == *"no ejecuta"* ]]; then
  ok "estatico: sinks heurísticos y no ejecucion"
else
  bad "estatico: sinks heurísticos y no ejecucion"
fi

# --- Ayuda y manual de usuario ---
help_out=$($ANALYZER --help 2>&1)
manual_out=$($ANALYZER --manual 2>&1)
if [[ $help_out == *"--manual"* && $manual_out == *"MANUAL DE USUARIO"* &&
      $manual_out == *"LIMITACIONES CONOCIDAS"* && $manual_out == *"ignore-rule"* ]]; then
  ok "cli: ayuda rapida y manual completo"
else
  bad "cli: ayuda rapida y manual completo"
fi

# --- Pruebas dinamicas (Iteracion 2): ejecutan el script bajo monitoreo ---
# Cabeceras opcionales en el script: # ANALYZER-ARGS: ..., # ANALYZER-ENV: K=V ..., # ANALYZER-STDIN: texto
for f in tests/positivos/*.sh tests/negativos/*.sh tests/recursivo/r*.sh; do
  name=$(basename "$f" .sh)
  exp="tests/expected_dyn/$name.tsv"
  [[ -f $exp ]] || continue
  args=$(sed -n 's/^# ANALYZER-ARGS: //p' "$f")
  envs=$(sed -n 's/^# ANALYZER-ENV: //p' "$f")
  stdin=$(sed -n 's/^# ANALYZER-STDIN: //p' "$f")
  opts=$(sed -n 's/^# ANALYZER-OPTS: //p' "$f")
  # shellcheck disable=SC2086
  got=$(printf '%s\n' "$stdin" | env $envs timeout 20 "$ANALYZER" -q --no-script-output --format=tsv $opts "$f" $args 2>/dev/null)
  if [[ $got == "$(<"$exp")" ]]; then ok "dinamica: $name"; else
    bad "dinamica: $name"
    diff <(printf '%s\n' "$got") "$exp" | sed 's/^/      /'
  fi
done

# --- Iteracion 4: codigo de salida, modos (RF-06) y exportacion JSON ---
dyn() { "$ANALYZER" -q --no-script-output --format=tsv "$@" 2>/dev/null; }
dyn tests/positivos/t06_eval.sh x >/dev/null; rc=$?
[[ $rc -eq 1 ]] && ok "exit 1: strict con alerta critica" || bad "exit strict critica (rc=$rc)"
dyn --mode=conservative tests/positivos/t06_eval.sh x >/dev/null; rc=$?
[[ $rc -eq 0 ]] && ok "exit 0: conservative con alerta critica" || bad "exit conservative (rc=$rc)"
dyn tests/negativos/n01_sin_fuentes.sh >/dev/null; rc=$?
[[ $rc -eq 0 ]] && ok "exit 0: sin alertas" || bad "exit sin alertas (rc=$rc)"

rf06=1
for f in tests/positivos/*.sh tests/negativos/*.sh tests/recursivo/r*.sh; do
  args=$(sed -n 's/^# ANALYZER-ARGS: //p' "$f")
  # shellcheck disable=SC2086
  ns=$(dyn --mode=strict "$f" $args </dev/null | grep -c '^ALERT')
  # shellcheck disable=SC2086
  nc=$(dyn --mode=conservative "$f" $args </dev/null | grep -c '^ALERT')
  ((ns >= nc)) || { rf06=0; printf '      %s: strict=%d conservative=%d\n' "$f" "$ns" "$nc"; }
done
((rf06)) && ok "rf-06: strict >= conservative en todos los scripts" || bad "rf-06: strict >= conservative"

tmpj=$(mktemp -d)
"$ANALYZER" -q --no-script-output --export=json "$tmpj/a.json" tests/positivos/t08_sin_comillas_subproceso.sh x >/dev/null 2>&1
"$ANALYZER" -q --no-script-output --export=json "$tmpj/v.json" tests/negativos/n01_sin_fuentes.sh >/dev/null 2>&1
if command -v python3 >/dev/null; then
  python3 - "$tmpj/a.json" "$tmpj/v.json" <<'PY' && ok "json: valido, campos minimos y lista vacia" || bad "json: validacion"
import json, sys
a = json.load(open(sys.argv[1])); v = json.load(open(sys.argv[2]))
need = {"file", "line", "severity", "source", "path", "sink", "cwe", "explanation"}
assert len(a["findings"]) == 2 and all(need <= set(f) for f in a["findings"])
assert [f["severity"] for f in a["findings"]] == ["HIGH", "CRITICAL"]
assert v["findings"] == []
PY
else skip=$((skip + 1)); printf 'SKIP  json: sin python3 para validar\n'; fi
out=$("$ANALYZER" -q --no-script-output --export=json /no/existe/dir/x.json tests/negativos/n01_sin_fuentes.sh 2>&1); rc=$?
[[ $rc -eq 0 && $out == *"no se pudo escribir"* && $out == *"Archivo:"* ]] && ok "json: error de escritura no interrumpe la consola" || bad "json: error de escritura (rc=$rc)"
"$ANALYZER" --export=json >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "cli: --export sin archivo (exit 2)" || bad "cli: --export sin archivo (rc=$rc)"
rm -rf "$tmpj"

# --- Iteracion 5: ignore-rule (CU04) y analisis recursivo (CU05) ---
out=$("$ANALYZER" -q --no-script-output tests/positivos/t09f_ignore_dos_lineas.sh true 2>/dev/null)
[[ $out == *"excluidas por directiva ignore-rule: 2"* && $out == *"Alertas generadas: 0"* ]] \
  && ok "p04-06: el reporte indica 2 lineas excluidas" || bad "p04-06: lineas excluidas"
out=$("$ANALYZER" -q --no-script-output -r tests/recursivo/r04_principal_y_secundario.sh true 2>/dev/null)
[[ $out == *"script principal"* && $out == *"script secundario"* && $out == *"Scripts analizados: 2"* ]] \
  && ok "p05-04: el reporte distingue principal y secundario" || bad "p05-04: origen del hallazgo"
tmpj=$(mktemp -d)
"$ANALYZER" -q --no-script-output -r --export=json "$tmpj/r.json" tests/recursivo/r04_principal_y_secundario.sh true >/dev/null 2>&1
"$ANALYZER" -q --no-script-output -r --export=json "$tmpj/u.json" tests/recursivo/r05_ruta_inexistente.sh true >/dev/null 2>&1; rc5=$?
if command -v python3 >/dev/null; then
  python3 - "$tmpj/r.json" "$tmpj/u.json" <<'PY' && ok "json: origen, archivos analizados y avisos" || bad "json: recursivo"
import json, sys
r = json.load(open(sys.argv[1])); u = json.load(open(sys.argv[2]))
assert [f["origin"] for f in r["findings"]] == ["main", "secondary"] and len(r["files_analyzed"]) == 2
assert len(u["warnings"]) == 1 and u["warnings"][0]["type"] == "UNRESOLVED" and len(u["findings"]) == 1
PY
else skip=$((skip + 1)); printf 'SKIP  json recursivo: sin python3\n'; fi
[[ $rc5 -eq 1 ]] && ok "p05-05: ruta inexistente avisa y continua (el hallazgo posterior se reporta)" || bad "p05-05 (rc=$rc5)"
out=$("$ANALYZER" -q --no-script-output tests/recursivo/r05_ruta_inexistente.sh true 2>&1)
[[ $out != *"no se encontro el script secundario"* ]] && ok "p05-03b: sin -r no se avisa de scripts secundarios" || bad "p05-03b"
rm -rf "$tmpj"

out=$("$ANALYZER" -q --no-script-output -r tests/recursivo/r01_source.sh true 2>/dev/null)
[[ $out == *'> eval "$dato"'* ]] && ok "p05: el codigo mostrado corresponde al archivo secundario" || bad "p05: codigo del secundario"

if command -v script >/dev/null; then
  c=$(TERM=xterm script -qc "$ANALYZER -q --no-script-output tests/positivos/t06_eval.sh x" /dev/null 2>/dev/null)
  n=$(NO_COLOR=1 script -qc "$ANALYZER -q --no-script-output tests/positivos/t06_eval.sh x" /dev/null 2>/dev/null)
  [[ $c == *$'\033[1;31m'* && $c == *$'\033[7m'* && $n != *$'\033'* ]] \
    && ok "rf-05: colores y linea resaltada en terminal (sin colores con NO_COLOR)" || bad "rf-05: colores en terminal"
else skip=$((skip + 1)); printf 'SKIP  rf-05: sin comando script para simular terminal\n'; fi

# --- Listas blancas: reconocimiento de expresiones regulares acotadas (unitaria) ---
wl_ok=1
while IFS= read -r re; do
  ( source src/lib/propagation.sh; _az_whitelist_regex "$re" ) || { wl_ok=0; printf '      deberia aceptarse: %s\n' "$re"; }
done <<'LISTA'
^[a-z]+$
^[A-Za-z0-9_.-]+$
^[[:alnum:]_]+$
^(start|stop|restart)$
^[0-9]{1,5}$
^[a-z0-9._/-]+$
^a\.b$
LISTA
while IFS= read -r re; do
  ( source src/lib/propagation.sh; _az_whitelist_regex "$re" ) && { wl_ok=0; printf '      deberia rechazarse: %s\n' "$re"; }
done <<'LISTA'
^.*$
^.+$
[a-z]+
^[a-z]+
^[^;]+$
^[a-z;]+$
^[a-z ]+$
^\S+$
^[a-z]+.$
^[a-z$]+$
^a.b$
^[a-z`]+$
^[a-z|]+$
LISTA
((wl_ok)) && ok "lista blanca: regex aceptadas y rechazadas correctamente" || bad "lista blanca: regex"

# --- Transparencia: el script se comporta igual con y sin monitoreo ---
for f in tests/equivalencia/*.sh; do
  a=$(bash "$f" 2>&1); b=$("$ANALYZER" -q "$f" 2>&1 >/dev/null)
  [[ $a == "$b" ]] && ok "equivalencia: $(basename "$f" .sh)" || { bad "equivalencia: $(basename "$f" .sh)"; diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") | sed 's/^/      /'; }
done

# --- Iteracion 6: empaquetado y portabilidad ---
./build.sh >/dev/null 2>&1
tmpi=$(mktemp -d)
cp dist/analyzer "$tmpi/analyzer"
cp tests/positivos/t06_eval.sh "$tmpi/script.sh"
# El script empaquetado funciona solo (sin src/ ni rules/), con entorno minimo y desde otro directorio
out=$(cd "$tmpi" && env -i PATH="$PATH" HOME="$tmpi" ANALYZER_LOG_DIR="$tmpi/log" ./analyzer --version 2>&1)
[[ $out == "analyzer "* ]] && ok "empaquetado: --version" || bad "empaquetado: --version ($out)"
out=$(cd "$tmpi" && env -i PATH="$PATH" HOME="$tmpi" ANALYZER_LOG_DIR="$tmpi/log" ./analyzer --yes -q --no-script-output script.sh x 2>&1); rc=$?
[[ $rc -eq 1 && $out == *"CWE-78"* ]] && ok "empaquetado: analisis autonomo (catalogo embebido)" || bad "empaquetado: analisis autonomo (rc=$rc)"
out=$(cd "$tmpi" && env -i PATH="$PATH" HOME="$tmpi" ANALYZER_LOG_DIR="$tmpi/log" ./analyzer --manual 2>&1)
[[ $out == *"MANUAL DE USUARIO"* && $out == *"LIMITACIONES CONOCIDAS"* ]] \
  && ok "empaquetado: manual embebido" || bad "empaquetado: manual embebido"
# Bash demasiado antiguo: se rechaza con codigo 2 (se simula elevando el minimo exigido)
sed 's/BASH_VERSINFO\[0\] < 4 ||/BASH_VERSINFO[0] < 99 ||/' dist/analyzer >"$tmpi/viejo"
bash "$tmpi/viejo" --version >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "portabilidad: Bash < 4.4 rechazado (exit 2)" || bad "portabilidad: version de Bash (rc=$rc)"
# Comando requerido ausente: error claro, codigo 2
out=$(env -i PATH="$tmpi/vacio" "$BASH" "$tmpi/analyzer" script.sh 2>&1); rc=$?
[[ $rc -eq 2 && $out == *"comando requerido"* ]] && ok "portabilidad: comando requerido ausente (exit 2)" || bad "portabilidad: comando ausente (rc=$rc)"
rm -rf "$tmpi"
tmpp=$(mktemp -d)
./install.sh --prefix="$tmpp" >/dev/null 2>&1
[[ -x $tmpp/bin/analyzer && $("$tmpp/bin/analyzer" --version) == "analyzer "* ]] && ok "install.sh: instala y ejecuta" || bad "install.sh: instalacion"
./install.sh --uninstall --prefix="$tmpp" >/dev/null 2>&1
[[ ! -e $tmpp/bin/analyzer ]] && ok "install.sh: desinstala" || bad "install.sh: desinstalacion"
rm -rf "$tmpp"

# --- Pruebas de la CLI (CU01: P01-02, P01-03, P01-04) ---
"$ANALYZER" /no/existe.sh >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "cli: archivo inexistente (exit 2)" || bad "cli: archivo inexistente (exit $rc)"

tmp=$(mktemp -d)
printf '\x00\x01\x02binario' >"$tmp/bin.dat"
"$ANALYZER" "$tmp/bin.dat" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "cli: archivo binario rechazado" || bad "cli: archivo binario (exit $rc)"

printf 'solo texto\n' >"$tmp/texto.txt"
"$ANALYZER" "$tmp/texto.txt" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "cli: texto que no es Bash rechazado" || bad "cli: texto no Bash (exit $rc)"

if [[ $(id -u) -ne 0 ]]; then
  printf '#!/bin/bash\n' >"$tmp/sinleer.sh"; chmod 000 "$tmp/sinleer.sh"
  "$ANALYZER" "$tmp/sinleer.sh" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 2 ]] && ok "cli: archivo no legible" || bad "cli: archivo no legible (exit $rc)"
else
  skip=$((skip + 1)); printf 'SKIP  cli: archivo no legible (root lee todo)\n'
fi

out=$("$ANALYZER" tests/negativos/n01_sin_fuentes.sh 2>&1)
[[ $out == *"No se identificaron fuentes"* ]] && ok "cli: mensaje sin fuentes (es)" || bad "cli: mensaje sin fuentes (es)"
out=$("$ANALYZER" --lang=en tests/negativos/n01_sin_fuentes.sh 2>&1)
[[ $out == *"No external sources"* ]] && ok "cli: mensaje sin fuentes (en)" || bad "cli: mensaje sin fuentes (en)"

"$ANALYZER" --opcion-rara tests/positivos/t01_posicional.sh >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "cli: opcion desconocida" || bad "cli: opcion desconocida (exit $rc)"

# --- Bitacora (CU01 postcondicion) ---
[[ -s $ANALYZER_LOG_DIR/analyzer.log ]] && ok "log: se genera la bitacora" || bad "log: se genera la bitacora"

# --- No debe haber conexiones de red (RNF-01): el codigo no invoca herramientas de red
# (los nombres como ssh solo aparecen como datos del catalogo de puntos sensibles) ---
if grep -rEq '(^|[;&|(]|\$\()[[:space:]]*(curl|wget|nc|ncat|telnet|ssh|scp)([[:space:]]|$)' src/; then
  bad "rnf-01: referencias a herramientas de red en src/"
else ok "rnf-01: sin herramientas de red en src/"; fi

rm -rf "$tmp"
printf '\nResumen: %d correctas, %d fallidas, %d omitidas\n' "$pass" "$fail" "$skip"
[[ $fail -eq 0 ]]
