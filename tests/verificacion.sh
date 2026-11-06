#!/usr/bin/env bash
# verificacion.sh - automatiza las 36 pruebas de verificacion de los casos de uso
# (CU01-CU06, tablas P01-xx ... P06-xx). Ejecutar SOLO en el entorno aislado.
#   ./tests/verificacion.sh      (ANALYZER=dist/analyzer para la version empaquetada)
cd "$(dirname "$0")/.." || exit 1
ANALYZER=${ANALYZER:-src/analyzer}
# Las pruebas dinamicas son deliberadas y se ejecutan dentro del laboratorio.
export ANALYZER_ALLOW_EXECUTION=1
export ANALYZER_LOG_DIR; ANALYZER_LOG_DIR=$(mktemp -d)
T=$(mktemp -d); trap 'rm -rf "$T" "$ANALYZER_LOG_DIR"' EXIT
pass=0 fail=0
chk() { # chk <id> <descripcion> <condicion: 0 = cumple>
  if [[ $3 -eq 0 ]]; then pass=$((pass + 1)); printf 'PASS  %s  %s\n' "$1" "$2"
  else fail=$((fail + 1)); printf 'FAIL  %s  %s\n' "$1" "$2"; fi
}
has()  { [[ $1 == *"$2"* ]]; }
a()    { "$ANALYZER" -q --no-script-output "$@" 2>&1; }          # salida combinada
ao()   { "$ANALYZER" -q --no-script-output "$@" 2>/dev/null; }   # solo reporte
P=tests/positivos N=tests/negativos R=tests/recursivo
c() { "$@"; echo $?; }

# ---------------- CU01: ejecutar analisis ----------------
out=$(ao $P/t08_sin_comillas_subproceso.sh x)
chk P01-01 "hallazgos con linea, severidad, origen y CWE + resumen" \
  $(has "$out" "CWE-78" && has "$out" "CRITICA" && has "$out" "Resumen por severidad" && has "$out" "Fuente"; echo $?)
"$ANALYZER" /no/existe.sh >/dev/null 2>&1; chk P01-02 "archivo inexistente -> exit 2" $([[ $? -eq 2 ]]; echo $?)
if [[ $(id -u) -ne 0 ]]; then
  printf '#!/bin/bash\n' >"$T/x.sh"; chmod 000 "$T/x.sh"; "$ANALYZER" "$T/x.sh" >/dev/null 2>&1; r=$?
else r=2; fi  # root lee todo: se cubre con directorio (no es archivo regular)
[[ $(id -u) -eq 0 ]] && { "$ANALYZER" "$T" >/dev/null 2>&1; r=$?; }
chk P01-03 "archivo no legible -> exit 2" $([[ $r -eq 2 ]]; echo $?)
printf '\x00\x01bin' >"$T/b.dat"; printf 'texto\n' >"$T/t.txt"
"$ANALYZER" "$T/b.dat" >/dev/null 2>&1; r1=$?; "$ANALYZER" "$T/t.txt" >/dev/null 2>&1; r2=$?
chk P01-04 "binario y texto no Bash rechazados" $([[ $r1 -eq 2 && $r2 -eq 2 ]]; echo $?)
out=$(a $N/n01_sin_fuentes.sh)
chk P01-05 "script limpio: informa que no hay riesgos" $(has "$out" "No se identificaron fuentes"; echo $?)
rm -f "$ANALYZER_LOG_DIR"/analyzer.log; a $N/n01_sin_fuentes.sh >/dev/null
chk P01-06 "existe el log de la sesion" $([[ -s $ANALYZER_LOG_DIR/analyzer.log ]]; echo $?)
"$ANALYZER" -q --no-script-output $P/t06_eval.sh x >/dev/null 2>&1; c1=$?
"$ANALYZER" -q --no-script-output $N/n01_sin_fuentes.sh >/dev/null 2>&1; c2=$?
chk P01-07 "exit 1 con critico, 0 sin criticos" $([[ $c1 -eq 1 && $c2 -eq 0 ]]; echo $?)

# ---------------- CU02: taint tracking ----------------
out=$(ao -v $P/t06_eval.sh x)
chk P02-01 "ruta fuente -> sink en hallazgo eval" $(has "$out" "eval" && has "$out" '$1'; echo $?)
out=$(ao -v $P/t05b_funcion.sh dato; ao -v $P/t05_propagacion.sh dato)
tsv=$("$ANALYZER" -q --no-script-output --format=tsv $P/t05b_funcion.sh dato 2>/dev/null)
chk P02-02 "la marca se propaga por variables y funcion" $(has "$tsv" 'procesar:$1 -> x'; echo $?)
tsv=$("$ANALYZER" -q --no-script-output --format=tsv $P/t05c_sobrescritura.sh dato 2>/dev/null)
chk P02-03 "sobrescritura con constante: sin alerta" $([[ $tsv != *ALERT* && $tsv == *UNTAINT* ]]; echo $?)
out=$(ao --mode=conservative $P/t11_lista_blanca_regex.sh abc)
chk P02-04 "dato validado (lista blanca): sin hallazgo en conservative" $(has "$out" "Alertas generadas: 0"; echo $?)
out=$(ao --mode=conservative $N/t07b_validado_conservative.sh dato)
chk P02-05 "modo conservative: flujo sospechoso no se reporta" $(has "$out" "Alertas generadas: 0"; echo $?)
out=$(ao $N/t07_validado_constante.sh dato)
chk P02-06 "modo strict: el mismo flujo se reporta" $(has "$out" "Alertas generadas: 1"; echo $?)
out=$(ao -v $P/t08_sin_comillas_subproceso.sh x)
n=$(grep -c '^ *Ruta' <<<"$out"); m=$(grep -c '^ *Codigo' <<<"$out")
chk P02-07 "cada hallazgo incluye la ruta completa (-v)" $([[ $n -eq $m && $n -ge 2 ]]; echo $?)

# ---------------- CU03: mensajes ----------------
out=$(ao $P/t06_eval.sh x)
chk P03-01 "resumen: linea, severidad, tipo y CWE-78" $(has "$out" "CWE-78" && has "$out" "CRITICA" && has "$out" "eval"; echo $?)
chk P03-02 "linea del hallazgo presente (campo Codigo)" $(has "$out" "Codigo"; echo $?)
out=$(ao -v $P/t06_eval.sh x)
chk P03-03 "con --verbose se muestra la ruta" $(has "$out" "Ruta"; echo $?)
out=$(ao $P/t06_eval.sh x)
chk P03-04 "sin --verbose no se muestra la ruta" $([[ $out != *"Ruta"* ]]; echo $?)
out=$(ao $P/t08_sin_comillas_subproceso.sh x)
chk P03-05 "varios hallazgos, cada uno con su CWE" $([[ $(grep -c 'Referencia' <<<"$out") -eq 2 ]]; echo $?)
out=$(ao $N/n01_sin_fuentes.sh)
chk P03-06 "sin hallazgos: no hay listado de alertas" $([[ $out != *"Alertas:"* ]]; echo $?)

# ---------------- CU04: ignore-rule ----------------
out=$(ao $P/t09_ignore_previa.sh true);        chk P04-01 "directiva en linea previa" $(has "$out" "Alertas generadas: 0"; echo $?)
out=$(ao $P/t09b_ignore_misma_linea.sh true);  chk P04-02 "directiva en la misma linea" $(has "$out" "Alertas generadas: 0"; echo $?)
out=$(ao $P/t09c_ignore_id.sh true);           chk P04-03 "ID coincidente excluye" $(has "$out" "Alertas generadas: 0"; echo $?)
out=$(ao $P/t09d_ignore_otro_id.sh true);      chk P04-04 "ID distinto: la alerta se genera" $(has "$out" "Alertas generadas: 1"; echo $?)
out=$(ao $P/t09e_ignore_alcance.sh true);      chk P04-05 "solo se omite la linea excluida" $(has "$out" "Alertas generadas: 1"; echo $?)
out=$(ao $P/t09f_ignore_dos_lineas.sh true);   chk P04-06 "reporte indica 2 lineas excluidas" $(has "$out" "excluidas por directiva ignore-rule: 2"; echo $?)

# ---------------- CU05: recursivo ----------------
out=$(ao -r $R/r01_source.sh true);  chk P05-01 "source: hallazgo del secundario" $(has "$out" "sec_eval.sh" && has "$out" "eval"; echo $?)
out=$(ao -r $R/r02_bash.sh true);    chk P05-02 "bash otro.sh: hallazgos consolidados" $(has "$out" "sec_eval.sh" && has "$out" "eval"; echo $?)
out=$(ao $R/r03_sin_recursivo.sh true); chk P05-03 "sin -r solo se analiza el principal" $(has "$out" "Alertas generadas: 0"; echo $?)
out=$(ao -r $R/r04_principal_y_secundario.sh true)
chk P05-04 "distingue principal de secundario" $(has "$out" "script principal" && has "$out" "script secundario"; echo $?)
out=$(a -r $R/r05_ruta_inexistente.sh true)
chk P05-05 "ruta no resoluble: avisa y continua (comportamiento registrado)" $(has "$out" "no se encontro el script secundario"; echo $?)

# ---------------- CU06: exportacion JSON ----------------
out=$("$ANALYZER" --no-script-output --export=json "$T/s.json" $P/t08_sin_comillas_subproceso.sh x 2>&1)
chk P06-01 "se crea el JSON y la consola confirma la ruta" $([[ -s $T/s.json ]] && has "$out" "$T/s.json"; echo $?)
if command -v python3 >/dev/null; then
  python3 - "$T/s.json" <<'PY'; r=$?
import json, sys
d = json.load(open(sys.argv[1]))
need = {"file", "line", "severity", "cwe", "path"}
assert d["findings"] and all(need <= set(f) for f in d["findings"])
PY
  chk P06-02 "cada hallazgo: linea, severidad, CWE, ruta, archivo" $r
  python3 -m json.tool "$T/s.json" >/dev/null 2>&1; chk P06-03 "JSON valido (json.tool)" $?
else
  chk P06-02 "(sin python3)" 1; chk P06-03 "(sin python3)" 1
fi
out=$(a --export=json /no/existe/dir/s.json $N/n01_sin_fuentes.sh); r=$?
chk P06-04 "sin permiso de escritura: avisa y no interrumpe" $([[ $r -eq 0 ]] && has "$out" "no se pudo escribir" && has "$out" "Archivo:"; echo $?)
a --export=json "$T/v.json" $N/n01_sin_fuentes.sh >/dev/null
r=1; command -v python3 >/dev/null && python3 -c "import json,sys; assert json.load(open(sys.argv[1]))['findings']==[]" "$T/v.json" && r=0
chk P06-05 "script limpio: JSON valido con lista vacia" $r

printf '\nVerificacion: %d correctas, %d fallidas (de 36)\n' "$pass" "$fail"
[[ $fail -eq 0 && $((pass + fail)) -eq 36 ]]
