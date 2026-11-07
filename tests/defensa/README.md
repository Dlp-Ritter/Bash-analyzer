# Scripts de defensa del Analizador Bash

Esta carpeta contiene escenarios preparados para la defensa oral del proyecto. Cada archivo tiene más de siete líneas de código, comentarios explicativos y una entrada controlada. La intención es que pueda responder, línea por línea, qué fuente detecta el analizador, cómo se propaga el dato y qué sink produce la alerta.

> **Importante:** el modo dinámico ejecuta el script analizado. Los ejemplos normales utilizan payloads inocuos, pero las demostraciones prácticas de los casos 1 y 5 incorporan una acción controlada sobre archivos dentro de `/tmp`. Nunca apuntes a archivos del proyecto, del usuario o del sistema. Ejecuta estas pruebas preferentemente dentro del laboratorio aislado del proyecto.

## Archivos

| Archivo | Escenario | Resultado esperado |
|---|---|---|
| `01_flujo_eval.sh` | Argumento → variables → función → `eval`; explotación controlada | Alerta crítica `EVAL`, `CWE-78` |
| `02_subshell_sin_comillas.sh` | Variable sin comillas y `bash -c` | `UNQUOTED` y `SUBSHELL` |
| `03_lista_blanca.sh` | Validación regex antes del sink | `SANITIZED` en `strict`; filtrado en `conservative` |
| `04_sobrescritura_constante.sh` | El taint se reemplaza por una constante | Sin alerta dinámica de sink |
| `05_principal_recursivo.sh` | Flujo hacia un archivo secundario | Hallazgo en `05_secundario.sh` con `--recursive` |
| `06_sin_flujo_peligroso.sh` | Control negativo basado solo en constantes | Sin alerta |

---

## 1. Preparación segura

Ejecute todo desde la raíz del proyecto:

```bash
cd /home/Leonel/Descargas/pg2P/proyecto-analizador-bash
```

Compruebe que Bash y el analizador están disponibles:

```bash
bash --version
./src/analyzer --help
```

Para probar la versión distribuible, sustituya `./src/analyzer` por `./dist/analyzer` en todos los comandos.

Verifique los permisos y, si es necesario, marque los scripts como ejecutables:

```bash
chmod +x tests/defensa/*.sh
```

La marca ejecutable no es indispensable cuando el analizador los invoca mediante Bash, pero facilita inspeccionarlos o ejecutarlos manualmente.

### Recomendación de aislamiento

Para una defensa real, ejecute el proyecto dentro de una VM o Docker sin red. Por ejemplo, utilice el laboratorio ya definido por el proyecto:

```bash
docker build -t analizador-bash-lab .

docker run --rm -it \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  analizador-bash-lab
```

No presente el modo dinámico como un sandbox. La confirmación `--yes` solo autoriza la ejecución; no bloquea permisos del script.

---

## 2. Cómo interpretar el resultado

Cada demostración debe explicarse con esta secuencia:

```text
fuente → propagación → función o asignación → sink → alerta
```

- **Fuente:** de dónde proviene el dato externo, por ejemplo `$1`.
- **Propagación:** copia, concatenación, parámetro o variable intermedia.
- **Sink:** operación que puede interpretar datos como código o argumentos.
- **Alerta:** clasificación, severidad, CWE y ruta observada.

### Códigos de salida

En modo `strict`, los casos con una alerta crítica normalmente terminan con código `1`. Eso no significa que el analizador haya fallado; significa que encontró un hallazgo crítico. Para no detener una demostración, use:

```bash
comando || codigo=$?
printf 'Código de salida: %s\\n' "${codigo:-0}"
```

No use `set -e` en una terminal de demostración si desea continuar después de una alerta.

### Diferencia entre estático y dinámico

- `--static`: no ejecuta el script; informa indicadores heurísticos.
- Modo dinámico: ejecuta el script y confirma los flujos que se observan durante ese recorrido.

La ausencia de una alerta dinámica solo demuestra que no se observó un flujo peligroso en esa ejecución. No demuestra seguridad universal.

---

# 3. Procedimientos detallados

## Caso 1: flujo completo hasta `eval`

### Archivo

```text
tests/defensa/01_flujo_eval.sh
```

### Qué debe explicar

1. `$1` es la fuente externa.
2. `entrada="$1"` copia el taint a `entrada`.
3. `preparada="prefijo-$entrada"` conserva el taint mediante interpolación.
4. `comando=...` crea un comando dinámico usando el dato.
5. `mostrar_comando "$comando"` pasa el dato a una función.
6. `local recibido="$1"` conserva el flujo dentro de la función.
7. `eval "$recibido"` es el sink `EVAL`.
8. La clasificación esperada es `CWE-78`, severidad crítica.

El payload usado es `echo DEFENSA_EVAL`; es inocuo porque solo imprime texto, pero sigue demostrando el problema de interpretar una entrada como código.

### Análisis estático

```bash
./src/analyzer --static --format=tsv \
  tests/defensa/01_flujo_eval.sh
```

Qué decir:

> El modo estático identifica patrones potenciales en el archivo sin ejecutar el payload. Por eso el hallazgo se considera heurístico y no una confirmación de recorrido.

### Análisis dinámico

```bash
./src/analyzer --yes --no-script-output --verbose \
  tests/defensa/01_flujo_eval.sh 'echo DEFENSA_EVAL'
```

Para una salida más fácil de leer:

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/01_flujo_eval.sh 'echo DEFENSA_EVAL' || true
```

El `|| true` solo evita que el código de salida crítico interrumpa una demostración automatizada; no oculta la alerta.

### Qué capturó el analizador

Debe buscar en el reporte:

- Archivo y línea de `eval`.
- Sink `EVAL`.
- CWE-78.
- Fuente `$1` o la ruta equivalente.
- Variables intermedias `entrada`, `preparada`, `comando` y el parámetro de función.
- Severidad `CRITICAL`.

### Pregunta probable

**¿Por qué es una alerta si el argumento solo contiene `echo`?**

Respuesta:

> Porque el problema no depende de que este payload concreto sea destructivo. El riesgo es que el programa usa `eval`, por lo que cualquier usuario que controle el argumento podría proporcionar otra cadena y hacer que el shell la interprete como código.

### Demostración práctica controlada: crear y eliminar un archivo temporal

El payload simple `rm prueba.txt` se imprime como texto en este script porque el valor se incorpora dentro de una cadena para `printf`. Para demostrar que todavía existe una inyección, se puede cerrar la comilla generada por el script y agregar una instrucción separada.

Utiliza solamente `/tmp`:

```bash
mkdir -p /tmp/demo-analizador
rm -f /tmp/demo-analizador/archivo_01.txt
```

Primero prueba una acción no destructiva para confirmar el efecto:

```bash
./tests/defensa/01_flujo_eval.sh \
  '"; touch /tmp/demo-analizador/archivo_01.txt; #'
```

Comprueba el resultado:

```bash
if [ -f /tmp/demo-analizador/archivo_01.txt ]; then
    echo 'La inyección creó el archivo temporal.'
else
    echo 'El archivo no fue creado.'
fi
```

El comando construido internamente se parece a:

```bash
printf '%s\\n' "prefijo-"; touch /tmp/demo-analizador/archivo_01.txt; #"
```

La comilla del payload cierra la cadena de `printf`; el punto y coma separa un nuevo comando y `#` comenta el resto de la expresión.

Para probar la eliminación de un archivo temporal:

```bash
touch /tmp/demo-analizador/prueba_01.txt

./tests/defensa/01_flujo_eval.sh \
  '"; rm -- /tmp/demo-analizador/prueba_01.txt; #'

if [ -f /tmp/demo-analizador/prueba_01.txt ]; then
    echo 'El archivo todavía existe.'
else
    echo 'El archivo temporal fue eliminado mediante eval.'
fi
```

### La misma demostración mediante el analizador

```bash
rm -f /tmp/demo-analizador/archivo_01_detectado.txt

./src/analyzer --yes --no-script-output --verbose \
  tests/defensa/01_flujo_eval.sh \
  '"; touch /tmp/demo-analizador/archivo_01_detectado.txt; #' || true
```

Después verifica:

```bash
ls -l /tmp/demo-analizador/archivo_01_detectado.txt
```

El reporte debe mostrar una alerta crítica `EVAL`/`CWE-78`. El `|| true` permite continuar aunque el analizador devuelva código `1` por haber encontrado una alerta; no bloquea ni oculta la ejecución.

### Qué debe decirse en la defensa

> El payload `rm prueba.txt` no funcionó directamente porque quedó dentro de una cadena de `printf`. Sin embargo, un atacante puede construir una entrada que cierre la comilla, agregue un comando y comente el resto. Esto demuestra que `eval` permite modificar la estructura del comando evaluado. El analizador detecta el flujo y lo reporta, pero no bloquea la acción; por eso esta prueba solo debe realizarse con archivos temporales en un entorno aislado.

### Precauciones de este ejemplo

- No sustituir `/tmp/demo-analizador` por el directorio del proyecto.
- No probar con `rm -rf`.
- No usar rutas del sistema, del usuario ni archivos importantes.
- Revisar el payload antes de pulsar Enter.
- Si se utiliza `--yes`, recordar que se está autorizando la ejecución real.

---

## Caso 2: `bash -c` y variable sin comillas

### Archivo

```text
tests/defensa/02_subshell_sin_comillas.sh
```

### Qué debe explicar

El script contiene dos sinks separados:

- `printf '%s\\n' $archivo`: expansión sin comillas, clasificada como `UNQUOTED` y relacionada con `CWE-88`.
- `bash -c "$comando"`: ejecución de una cadena como código de shell, clasificada como `SUBSHELL` y relacionada con `CWE-78`.

El argumento recomendado es `echo DEFENSA_SUBSHELL`. No contiene espacios ni comandos destructivos, por lo que el comportamiento de la demostración es predecible.

### Comando

```bash
./src/analyzer --yes --no-script-output --verbose \
  tests/defensa/02_subshell_sin_comillas.sh 'echo DEFENSA_SUBSHELL' || true
```

En TSV:

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/02_subshell_sin_comillas.sh 'echo DEFENSA_SUBSHELL' || true
```

### Qué capturó el analizador

- `$1` como fuente.
- La asignación a `entrada` y `archivo`.
- La expansión sin comillas en la función `mostrar_nombre`.
- El paso del comando a `bash -c` en `ejecutar_subshell`.
- Dos sinks distintos dentro del mismo archivo.

### Pregunta probable

**¿Por qué una expansión sin comillas es diferente de `bash -c`?**

Respuesta:

> La expansión sin comillas puede dividir el contenido en palabras y modificar los argumentos recibidos por el comando. `bash -c`, en cambio, interpreta una cadena como instrucciones de shell. Ambos son riesgos diferentes y por eso aparecen con reglas y severidades distintas.

---

## Caso 3: validación mediante lista blanca

### Archivo

```text
tests/defensa/03_lista_blanca.sh
```

### Qué debe explicar

1. `$1` se marca como fuente.
2. La expresión `^[a-z]+$` limita el valor a letras minúsculas.
3. Si la entrada no cumple, el script termina antes del sink.
4. Si cumple, el analizador reconoce una validación.
5. `eval` sigue siendo una operación sensible, aunque la entrada esté restringida.

Use `echo` como entrada porque cumple la expresión y produce una acción inocua:

```bash
./src/analyzer --yes --no-script-output \
  tests/defensa/03_lista_blanca.sh echo || true
```

### Comparación `strict` y `conservative`

Modo estricto:

```bash
./src/analyzer --yes --mode=strict --no-script-output --format=tsv \
  tests/defensa/03_lista_blanca.sh echo || true
```

Modo conservador:

```bash
./src/analyzer --yes --mode=conservative --no-script-output --format=tsv \
  tests/defensa/03_lista_blanca.sh echo
```

### Resultado que se debe explicar

- En `strict`, el reporte dinámico identifica el sink como `EVAL/SAN`: conserva el sink y marca que la entrada pasó por una validación reconocida.
- En `conservative`, ese hallazgo puede filtrarse porque el dato fue validado mediante una regla reconocida.
- La validación no convierte automáticamente cualquier uso de `eval` en seguro; solamente reduce el conjunto de entradas aceptadas.

### Prueba de rechazo

```bash
./src/analyzer --yes --no-script-output \
  tests/defensa/03_lista_blanca.sh 'echo DEFENSA; rm -f /tmp/no_debe_existir' || true
```

La expresión no acepta espacios, punto y coma ni otros caracteres. El script debe terminar en la validación y no llegar a `eval`.

### Pregunta probable

**¿Por qué todavía se reporta algo en `strict`?**

Respuesta:

> `strict` prioriza sensibilidad y conserva hallazgos que requieren revisión. `conservative` aplica una política de menor ruido. La clasificación no afirma que el payload válido sea automáticamente explotable; documenta que existe un sink que recibe un dato originalmente externo.

---

## Caso 4: sobrescritura por constante

### Archivo

```text
tests/defensa/04_sobrescritura_constante.sh
```

### Qué debe explicar

1. `entrada="$1"` inicia un flujo contaminado.
2. `intermedia="$entrada"` propaga el taint.
3. `intermedia="valor_constante"` reemplaza el dato externo.
4. La función recibe una constante conocida.
5. El uso final está citado y no ejecuta código dinámico.

### Comando dinámico

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/04_sobrescritura_constante.sh dato_externo
```

### Comando estático

```bash
./src/analyzer --static --format=tsv \
  tests/defensa/04_sobrescritura_constante.sh
```

### Qué debe observar

El estático puede mostrar la presencia de una fuente y las asignaciones porque trabaja por patrones. El dinámico debe reconocer que la variable fue sobrescrita y no debe producir una alerta crítica de `eval`, `bash -c` o comando dinámico: ninguno de esos sinks existe en el archivo.

### Pregunta probable

**¿Esto prueba que el analizador elimina todos los falsos positivos?**

Respuesta:

> No. Demuestra un caso concreto de sobrescritura que está dentro del alcance validado. No permite afirmar que el sistema comprenda toda forma posible de saneamiento, aliasing o reasignación compleja en Bash.

---

## Caso 5: análisis recursivo

### Archivos

```text
tests/defensa/05_principal_recursivo.sh
tests/defensa/05_secundario.sh
```

### Qué debe explicar

- El archivo principal recibe `$1`.
- El valor se conserva en `principal`.
- `source tests/defensa/05_secundario.sh "$principal"` carga una ruta literal.
- El secundario recibe el parámetro.
- El secundario lo incorpora en `transformado`.
- La función `informar` pasa el dato a `eval`.
- El sink está en el segundo archivo, no en el principal.

### Comando recomendado

```bash
./src/analyzer --yes --recursive --no-script-output --verbose \
  tests/defensa/05_principal_recursivo.sh 'echo DEFENSA_RECURSIVA' || true
```

En TSV:

```bash
./src/analyzer --yes --recursive --no-script-output --format=tsv \
  tests/defensa/05_principal_recursivo.sh 'echo DEFENSA_RECURSIVA' || true
```

### Contraste sin recursividad

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/05_principal_recursivo.sh 'echo DEFENSA_RECURSIVA' || true
```

Explique que sin `--recursive` el analizador se limita al alcance configurado y puede no reportar el sink del archivo secundario. Con `--recursive`, intenta analizar el archivo cargado y puede presentar el origen como secundario.

### Importante sobre la ruta

Ejecute desde la raíz del repositorio. La ruta usada en `source` es relativa al directorio actual:

```text
tests/defensa/05_secundario.sh
```

Si ejecuta el script desde otra carpeta, la ruta puede no resolverse. Eso sería un problema del contexto de ejecución, no una falla del mecanismo de taint tracking.

### Pregunta probable

**¿Por qué no analizar siempre todos los archivos recursivamente?**

Respuesta:

> El análisis recursivo aumenta cobertura, pero también puede incorporar archivos que no forman parte del objetivo, seguir rutas complejas o incrementar el costo de ejecución. Por eso es opcional y se activa explícitamente con `--recursive`.

### Demostración práctica controlada en el archivo secundario

Este caso permite demostrar que la entrada no confiable atraviesa dos archivos antes de llegar al sink. El objetivo es crear un archivo temporal desde el `eval` ubicado en `05_secundario.sh`.

Prepara el directorio temporal:

```bash
mkdir -p /tmp/demo-analizador
rm -f /tmp/demo-analizador/archivo_recursivo.txt
```

Ejecuta el principal con un payload controlado:

```bash
./tests/defensa/05_principal_recursivo.sh \
  '"; touch /tmp/demo-analizador/archivo_recursivo.txt; #'
```

Comprueba el efecto:

```bash
if [ -f /tmp/demo-analizador/archivo_recursivo.txt ]; then
    echo 'El archivo fue creado desde el sink del secundario.'
else
    echo 'El archivo no fue creado.'
fi
```

La ruta conceptual es:

```text
$1 del principal
  → entrada
  → principal
  → source 05_secundario.sh
  → recibido en el secundario
  → transformado
  → informar
  → comando_local
  → eval
  → touch /tmp/demo-analizador/archivo_recursivo.txt
```

### Ejecutarlo mediante el analizador con `--recursive`

```bash
rm -f /tmp/demo-analizador/archivo_recursivo_detectado.txt

./src/analyzer --yes --recursive --no-script-output --verbose \
  tests/defensa/05_principal_recursivo.sh \
  '"; touch /tmp/demo-analizador/archivo_recursivo_detectado.txt; #' || true
```

Verifica el archivo:

```bash
ls -l /tmp/demo-analizador/archivo_recursivo_detectado.txt
```

El reporte debe ubicar el hallazgo en:

```text
tests/defensa/05_secundario.sh
```

y mostrar un sink `EVAL` asociado con `CWE-78`. Esta es la utilidad principal de `--recursive`: no solo analiza el archivo inicial, sino que sigue el archivo cargado mediante `source` dentro del alcance implementado.

### Comparación con y sin `--recursive`

Con recursividad:

```bash
./src/analyzer --yes --recursive --no-script-output --format=tsv \
  tests/defensa/05_principal_recursivo.sh \
  'echo DEFENSA_RECURSIVA' || true
```

Sin recursividad:

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/05_principal_recursivo.sh \
  'echo DEFENSA_RECURSIVA' || true
```

`--recursive` modifica el alcance de observación y reporte; no convierte la ejecución en segura. El archivo secundario puede ejecutarse como parte normal de `source` aunque no se active el análisis recursivo. Por ese motivo ambas pruebas, especialmente la que usa `touch`, deben realizarse únicamente con archivos temporales y en aislamiento.

### Qué debe decirse en la defensa

> El análisis recursivo es necesario porque el sink no está en el archivo principal. El dato nace en `$1`, se pasa al archivo secundario mediante `source` y finalmente llega a `eval`. Sin `--recursive`, la herramienta puede no mostrar el hallazgo del secundario, aunque el shell siga ejecutando ese archivo. Esto demuestra que recursividad es una capacidad de cobertura y trazabilidad, no un mecanismo de bloqueo.

### Precauciones específicas

- Ejecutar desde la raíz del proyecto porque la ruta de `source` es relativa.
- Confirmar que el objetivo se encuentra bajo `/tmp/demo-analizador`.
- No cambiar el payload por una ruta del proyecto.
- No utilizar `rm -rf` ni comandos de red.
- No interpretar `--recursive` como aislamiento o protección.

---

## Caso 6: control sin flujo peligroso

### Archivo

```text
tests/defensa/06_sin_flujo_peligroso.sh
```

### Qué debe explicar

- Todos los valores provienen de constantes.
- No existe `$1`, `$@`, `read`, entorno ni lectura externa.
- El mensaje se pasa como parámetro de una función.
- `printf` utiliza comillas.
- No existe `eval`, `bash -c`, `source`, `ssh` ni comando seleccionado por variable.

### Comandos

```bash
./src/analyzer --static --format=tsv \
  tests/defensa/06_sin_flujo_peligroso.sh

./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/06_sin_flujo_peligroso.sh ignorado
```

### Resultado esperado

No debe existir una alerta crítica por flujo externo. El argumento `ignorado` se entrega por uniformidad de la demostración, pero el script no lo utiliza.

### Pregunta probable

**¿Por qué es importante incluir un caso negativo?**

Respuesta:

> Un detector no se evalúa únicamente por encontrar positivos. También debe evitar alertar cuando no hay fuente externa ni sink sensible. Este caso sirve como control para discutir falsos positivos.

---

# 4. Demostración recomendada completa

Utilice esta secuencia en la defensa:

## Paso 1: mostrar ayuda

```bash
./src/analyzer --help
```

Explique que `--help` es la ayuda rápida de una CLI y que `--manual` presenta la documentación completa.

## Paso 2: mostrar el archivo

```bash
nl -ba tests/defensa/01_flujo_eval.sh
```

Señale la fuente, las variables intermedias, la función y el sink.

## Paso 3: análisis estático

```bash
./src/analyzer --static --format=tsv \
  tests/defensa/01_flujo_eval.sh
```

Repita que no ejecuta el script.

## Paso 4: análisis dinámico

```bash
./src/analyzer --yes --no-script-output --verbose \
  tests/defensa/01_flujo_eval.sh 'echo DEFENSA_EVAL' || true
```

Explique la diferencia entre potencial estático y flujo observado dinámicamente.

## Paso 5: mostrar un control negativo

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/04_sobrescritura_constante.sh dato_externo
```

Explique la sobrescritura.

## Paso 6: demostrar severidades

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/02_subshell_sin_comillas.sh 'echo DEFENSA_SUBSHELL' || true
```

Diferencie `UNQUOTED` de `SUBSHELL`.

## Paso 7: demostrar política de validación

```bash
./src/analyzer --yes --mode=strict --no-script-output --format=tsv \
  tests/defensa/03_lista_blanca.sh echo || true

./src/analyzer --yes --mode=conservative --no-script-output --format=tsv \
  tests/defensa/03_lista_blanca.sh echo
```

## Paso 8: demostrar recursividad

```bash
./src/analyzer --yes --recursive --no-script-output --format=tsv \
  tests/defensa/05_principal_recursivo.sh 'echo DEFENSA_RECURSIVA' || true
```

## Paso 9: cerrar con el caso limpio

```bash
./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/06_sin_flujo_peligroso.sh ignorado
```

---

# 5. JSON y evidencia para la terna

Para guardar un reporte de evidencia:

```bash
mkdir -p /tmp/evidencia-analizador
./src/analyzer --yes --no-script-output \
  --export=json /tmp/evidencia-analizador/01_eval.json \
  tests/defensa/01_flujo_eval.sh 'echo DEFENSA_EVAL' || true
```

Si `jq` está instalado:

```bash
jq '.' /tmp/evidencia-analizador/01_eval.json
```

Para mostrar solo los campos principales:

```bash
jq '.findings[] | {file, line, severity, source, sink, cwe, confidence}' \
  /tmp/evidencia-analizador/01_eval.json
```

No confunda la salida JSON con una prueba independiente: es otra representación del mismo análisis. La evidencia más fuerte combina el archivo de prueba, el comando reproducible, la salida y la explicación de la ruta.

---

# 6. Ejecutar todos los escenarios sin detenerse

El siguiente bloque continúa aunque un caso crítico devuelva código `1`:

```bash
set +e

./src/analyzer --static --format=tsv \
  tests/defensa/01_flujo_eval.sh

./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/01_flujo_eval.sh 'echo DEFENSA_EVAL'

./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/02_subshell_sin_comillas.sh 'echo DEFENSA_SUBSHELL'

./src/analyzer --yes --mode=conservative --no-script-output --format=tsv \
  tests/defensa/03_lista_blanca.sh echo

./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/04_sobrescritura_constante.sh dato_externo

./src/analyzer --yes --recursive --no-script-output --format=tsv \
  tests/defensa/05_principal_recursivo.sh 'echo DEFENSA_RECURSIVA'

./src/analyzer --yes --no-script-output --format=tsv \
  tests/defensa/06_sin_flujo_peligroso.sh ignorado
```

Para hacerlo con el ejecutable distribuible:

```bash
ANALYZER=./dist/analyzer
"$ANALYZER" --help
```

Luego sustituya `./src/analyzer` por `"$ANALYZER"` en los comandos anteriores.

---

# 7. Validación automática del proyecto

Los casos de defensa son demostraciones guiadas. No sustituyen la suite del proyecto.

```bash
./tests/run_tests.sh
./tests/verificacion.sh
```

Con el ejecutable distribuible:

```bash
ANALYZER=dist/analyzer ./tests/run_tests.sh
ANALYZER=dist/analyzer ./tests/verificacion.sh
```

Si el entorno de la suite exige permiso explícito para ejecución:

```bash
ANALYZER_ALLOW_EXECUTION=1 ./tests/run_tests.sh
```

---

# 8. Errores frecuentes durante la defensa

## Ejecutar dinámico sin aislamiento

Incorrecto:

```bash
./src/analyzer --yes script-desconocido.sh
```

Correcto: usar primero `--static`; si se necesita dinámico, utilizar un script controlado y un laboratorio aislado.

## Olvidar `--yes`

En una terminal interactiva el analizador puede solicitar confirmación. Para una demostración repetible, use `--yes` únicamente después de verificar el script.

## Interpretar código 1 como fallo del analizador

Un código `1` en `strict` puede significar que se encontró una alerta crítica. Observe la salida antes de concluir que ocurrió un error.

## Ejecutar desde la carpeta equivocada

El caso recursivo usa una ruta relativa. Ejecute desde la raíz del repositorio para que `source tests/defensa/05_secundario.sh` pueda resolverse.

## Confundir `--static` con confirmación

El estático puede mostrar un sink potencial aunque la rama no se ejecute. No diga que el estático confirmó una explotación.

## Usar un payload destructivo

No utilice `rm`, `curl`, `wget`, `sudo`, conexiones SSH ni comandos que modifiquen el sistema. `echo DEFENSA_*` es suficiente para demostrar el flujo.

## Mezclar salida del script y salida del analizador

Use `--no-script-output` para que la terminal muestre principalmente el reporte del analizador. Esto no impide que el script se ejecute; solo reduce su salida visible.

---

# 9. Respuestas breves para cada caso

- **Caso 1:** “La fuente `$1` se propaga por variables y una función hasta `eval`, por eso aparece `CWE-78` crítico.”
- **Caso 2:** “La expansión sin comillas afecta la separación de argumentos; `bash -c` interpreta una cadena como código. Son dos sinks diferentes.”
- **Caso 3:** “La lista blanca limita el dato. `strict` conserva el hallazgo saneado; `conservative` reduce ese ruido.”
- **Caso 4:** “El taint inicialmente existe, pero la variable se reemplaza por una constante antes de cualquier sink.”
- **Caso 5:** “La ruta del flujo cruza a un archivo secundario; `--recursive` amplía el alcance de análisis.”
- **Caso 6:** “Es un control negativo: solo hay constantes, usos citados y ningún sink dinámico.”

---

# 10. Checklist antes de la defensa

- [ ] Estoy en la raíz del proyecto.
- [ ] `./src/analyzer --help` funciona.
- [ ] Revisé el contenido de los seis scripts.
- [ ] Probé cada comando una vez.
- [ ] Tengo claro qué línea es fuente y qué línea es sink.
- [ ] Sé explicar `strict` y `conservative`.
- [ ] Sé explicar que el modo dinámico no es un sandbox.
- [ ] Uso argumentos benignos como `echo DEFENSA_EVAL`.
- [ ] Tengo un caso positivo y uno negativo.
- [ ] Sé interpretar el código de salida `1`.
- [ ] Para el caso recursivo ejecuto desde la raíz.
- [ ] No afirmo que el analizador detecte todas las vulnerabilidades.
- [ ] No afirmo que reemplace a ShellCheck.
- [ ] Si algo no fue validado, lo presento como limitación o trabajo futuro.
