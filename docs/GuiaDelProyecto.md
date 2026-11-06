# Analizador Dinámico en Tiempo Real de Inyección de Comandos en Bash

**Versión 1.0.0** · Proyecto de Graduación II · Universidad Mariano Gálvez de Guatemala
**Autor:** Duglas Leonel Pop Guitz

---

## 1. ¿Qué es, en una frase?

Una herramienta de línea de comandos, escrita en Bash puro, que **ejecuta un script Bash bajo observación y avisa si un dato controlado por un usuario externo llega a una instrucción peligrosa** (por ejemplo `eval "$1"`), indicando línea, severidad, ruta del dato y tipo de debilidad (CWE).

Funciona 100 % en local: no usa red, no envía nada a ningún servicio y no necesita instalar dependencias más allá de Bash 4.4+ y las utilidades estándar (`cat`, `sed`, `env`, `mktemp`, ...).

## 2. El problema que resuelve

La **inyección de comandos** ocurre cuando un script construye una orden con datos que alguien más controla:

```bash
#!/bin/bash
eval "ls $1"      # si $1 es  "; rm -rf ~"  se ejecuta también el rm
```

Es fácil de escribir y difícil de ver a simple vista cuando el dato pasa por varias variables y funciones antes de llegar al punto peligroso. Los analizadores estáticos suelen fallar porque no saben qué valores toman las variables en ejecución. Esta herramienta **observa la ejecución real** y sigue el dato paso a paso.

## 3. Cómo funciona (explicado sin tecnicismos)

Imagina que se le pone una **tinta de color** a todo lo que entra al script desde afuera. Luego se mira por dónde se derrama la tinta:

1. **Fuentes** (de dónde entra la tinta): argumentos `$1`, `$@`, variables de entorno, lectura de archivos o de la entrada estándar (`read`, `cat < archivo`), resultado de comandos.
2. **Propagación** (cómo se esparce): asignaciones (`b="$a"`), interpolaciones (`"x-$a"`), sustituciones de comandos, bucles `for`, paso de argumentos a funciones.
3. **Limpieza**: si la variable se sobrescribe con una constante, o se **valida** (lista blanca) o se **sanea** (`printf '%q'`), la tinta se quita o se rebaja.
4. **Puntos sensibles / sinks** (donde la tinta es peligrosa): `eval`, `bash -c`, `source`, ejecutar el dato como comando, `ssh` con comando remoto, o usar la variable sin comillas.

Si la tinta llega a un punto sensible, se genera una **alerta**.

### Cómo observa la ejecución (para quien pregunte "¿y eso cómo se hace?")

- Se genera en tiempo de ejecución un archivo "monitor" y se le dice a Bash que lo cargue antes del script (`BASH_ENV`).
- El monitor activa un `trap DEBUG`, que Bash dispara **antes de cada comando**, y registra qué comando va a correr y con qué variables.
- Los eventos se escriben a un descriptor de archivo aparte y el analizador los procesa con las reglas del catálogo.
- El monitoreo es **transparente**: el script se comporta igual con y sin monitor (hay pruebas de equivalencia que lo comprueban, p. ej. `BASH_REMATCH`, `$_` y opciones `set -e/-u/-x`).

## 4. Qué detecta (catálogo de puntos sensibles)

| Clave | Severidad | CWE | Qué significa |
|---|---|---|---|
| `EVAL` | CRÍTICA | CWE-78 | `eval` con dato externo |
| `SUBSHELL` | CRÍTICA | CWE-78 | `bash -c "$dato"`, `sh -c ...` |
| `EXECCMD` | CRÍTICA | CWE-78 | El dato decide qué programa corre (directo o vía `sudo`, `exec`, `xargs`, `env`, `nohup`, `nice`, `timeout`, `command`...) |
| `SOURCEFILE` | CRÍTICA | CWE-94 | `source "$dato"` / `. "$dato"` |
| `SSHCMD` | CRÍTICA | CWE-78 | El dato forma parte del comando remoto de `ssh` |
| `UNQUOTED` | ALTA | CWE-88 | Variable contaminada **sin comillas** (word splitting y comodines) |
| `SANITIZED` | MEDIA | CWE-20 | Dato saneado/validado, pero strict pide confirmación |
| `LOWRISK` | MEDIA | CWE-20 | Sin comillas pero en un comando que solo imprime (`echo`, `printf`) |
| `CONSTANT` | INFORMATIVA | — | Patrón inseguro sin dato externo asociado |

Las reglas viven en `rules/sources.conf` (formato `SINK_<CLAVE>=SEVERIDAD|CWE|descripción_es|descripción_en`) y se pueden ajustar sin tocar el código.

### Validaciones reconocidas (rebajan la alerta a MEDIA, o la quitan en modo conservative)

- `printf '%q'` capturado con `$(...)`.
- Lista blanca con regex acotada: `[[ $x =~ ^[a-z]+$ ]] || exit 1`.
- Comparación con literal: `[[ $x == "start" ]]` (y negadas con `!` / `!=`).
- `case "$x" in start|stop) ... ;; *) exit 1 ;; esac` con patrones literales (bloques multilínea).

**No** cuentan como validación: regex laxas (`^.*$`), sin anclas, clases que admitan `;`, `$`, comillas o espacios, y patrones de `case` con `*` o `?` (p. ej. `[a-z]*)`).

## 5. Instalación y uso

```bash
tar -xzf proyecto-analizador-bash-1.0.0.tar.gz
cd proyecto-analizador-bash

./src/analyzer script.sh                 # directo desde el código fuente
./install.sh                             # instala en ~/.local/bin/analyzer
./install.sh --prefix=/opt/az            # otro destino
./install.sh --uninstall                 # desinstala
analyzer --version                       # analyzer 1.0.0
```

> **Advertencia importante:** el modo dinámico **ejecuta realmente** el script analizado. Úsalo en una VM o contenedor, o usa `--static`.

### Opciones

| Opción | Efecto |
|---|---|
| `<script.sh> [args...]` | Script a analizar; los argumentos siguientes se pasan al script |
| `--mode=strict\|conservative` | Rigurosidad (por defecto `strict`) |
| `-r`, `--recursive` | Analiza también los scripts secundarios (`source`, `bash otro.sh`) |
| `-v`, `--verbose` | Agrega la ruta completa del dato y etapas intermedias |
| `--export=json <archivo>` | Exporta los hallazgos a JSON |
| `--format=text\|tsv` | Formato de salida |
| `--static` | Solo análisis estático (no ejecuta el script) |
| `--lang=es\|en` | Idioma de la interfaz (español por defecto) |
| `-q`, `--quiet` | Sin avisos informativos |
| `--no-script-output` | Descarta la salida del script analizado |
| `-h`, `--help` / `-V`, `--version` | Ayuda / versión |

### Código de salida

| Código | Significado |
|---|---|
| `0` | Correcto (o modo conservative, que nunca falla por alertas) |
| `1` | Modo strict con al menos una alerta CRÍTICA |
| `2` | Error de uso o de archivo (no existe, no legible, binario, no es Bash, Bash < 4.4, falta una utilidad) |

Esto permite usarlo en integración continua: `analyzer script.sh || echo "revisar"`.

### Modos `strict` y `conservative`

- **strict** (por defecto): reporta todo lo que el catálogo marque, incluso datos saneados (MEDIA).
- **conservative**: solo muestra severidades **CRÍTICA y ALTA**; elimina el ruido de lo saneado o de bajo riesgo y siempre termina con código 0.

La severidad la deciden las reglas; el modo solo **filtra**.

## 6. Ejemplos de uso

### Ejemplo 1 — Un script con tres problemas

`vulnerable.sh`:

```bash
#!/bin/bash
archivo=$1
rm $archivo
destino=$(printf '%q' "$2")
eval "echo guardado en $destino"
bash -c "$3"
```

```bash
analyzer vulnerable.sh a.txt dest "echo hola"
```

Salida (resumida):

```
Alertas generadas: 3

  [ALTA] vulnerable.sh:3  variable contaminada sin entrecomillar (CWE-88)
    Codigo:          > rm $archivo
    Fuente:          $1
    Punto sensible:  rm

  [MEDIA] vulnerable.sh:5  dato saneado o validado con lista blanca (CWE-20)
    Codigo:          > eval "echo guardado en $destino"
    Fuente:          $2
    Punto sensible:  eval

  [CRITICA] vulnerable.sh:6  subproceso con dato no validado (CWE-78)
    Codigo:          > bash -c "$3"
    Fuente:          $3
    Punto sensible:  bash

Resumen por severidad:
  CRITICA 1 · ALTA 1 · MEDIA 1
```

El código de salida es `1` (hay una CRÍTICA en modo strict). Con `--mode=conservative` solo aparecen la ALTA y la CRÍTICA, y el código de salida es `0`.

### Ejemplo 2 — Ver la ruta completa del dato (`-v`)

```bash
analyzer -v --lang=en script.sh dato
```

Muestra las etapas: fuentes observadas, propagación (`$1 -> a -> procesar:$1 -> x`), usos y variables limpiadas. Es ideal para explicar *por qué* se generó una alerta.

### Ejemplo 3 — Solo análisis estático

```bash
analyzer --static --format=tsv script.sh
```

No ejecuta nada; lista las fuentes externas que detecta en el código.

### Ejemplo 4 — Excluir una línea (falso positivo aceptado)

```bash
# ignore-rule
eval "$1"                     # directiva en la línea anterior

eval "$1"   # ignore-rule     # o al final de la misma línea

# ignore-rule:EVAL            # solo ignora la regla EVAL
eval "$1"
```

El reporte indica cuántas líneas se excluyeron: `Lineas excluidas por directiva ignore-rule: N`. Un ID distinto no excluye la alerta.

### Ejemplo 5 — Seguir scripts secundarios (`-r`)

```bash
# principal.sh
source ./libreria.sh "$1"
```

```bash
analyzer -r principal.sh dato
```

El reporte consolida hallazgos de ambos archivos, indica el **origen** (`script principal` / `script secundario`) y la cantidad de scripts analizados. Si un secundario no existe, se **avisa y se continúa**.

### Ejemplo 6 — Exportar a JSON

```bash
analyzer --export=json hallazgos.json script.sh dato
python3 -m json.tool hallazgos.json
```

Campos: `file`, `mode`, `script_exit_status`, `summary`, `excluded_lines`, `files_analyzed`, `warnings` y `findings[]` (cada uno con `file`, `line`, `origin`, `severity`, `source`, `path[]`, `sink`, `type`, `cwe`, `explanation`). Si no hay hallazgos se genera un JSON válido con la lista vacía; si no se puede escribir el archivo, se avisa y el análisis continúa.

### Ejemplo 7 — En integración continua

```bash
analyzer -q --no-script-output --mode=strict deploy.sh test-input
test $? -eq 1 && { echo "Hay riesgo de inyección"; exit 1; }
```

## 7. Cómo explicárselo a terceras personas

### En 30 segundos (para el jurado o un compañero)

> "Es un detector de inyección de comandos para scripts Bash. En vez de leer el código y adivinar, **lo ejecuta de forma vigilada** y sigue los datos que vienen de afuera —argumentos, variables de entorno, archivos— para ver si llegan a instrucciones como `eval` o `bash -c`. Si llegan, avisa en qué línea, qué tan grave es y qué debilidad CWE corresponde. Es 100 % local y está hecho en Bash puro."

### Con una analogía (para no técnicos)

> "Piensa en un laboratorio de análisis de agua. Se le echa un colorante a lo que entra a la tubería y se mira si sale en el grifo de beber. Aquí el colorante son los datos del usuario, y el grifo son los comandos peligrosos."

### Preguntas frecuentes

| Pregunta | Respuesta corta |
|---|---|
| ¿Por qué ejecuta el script? | Porque solo en ejecución se conocen los valores reales y las rutas que se toman; el estático no puede. Para no ejecutar, existe `--static`. |
| ¿Es seguro ejecutarlo? | Ejecuta el script analizado igual que si lo corrieras tú; por eso se recomienda un entorno aislado. |
| ¿Por qué Bash puro? | Cero dependencias y portabilidad: corre donde haya Bash 4.4+. |
| ¿Detecta todo? | No. Solo ve lo que se ejecuta (ramas no tomadas no se observan) y rastrea variables por nombre. Ver limitaciones. |
| ¿Qué es CWE? | Catálogo público de tipos de debilidad de software; CWE-78 es inyección de comandos del SO. |
| ¿Por qué hay modo conservative? | Para reducir ruido: solo severidades CRÍTICA y ALTA. |
| ¿Se puede ampliar? | Sí: los sinks y severidades están en `rules/sources.conf`. |

### Guion sugerido para una demo de 5 minutos

1. Mostrar un script con `eval "$1"` y explicar el riesgo con un valor malicioso.
2. Ejecutar `analyzer script.sh "ls; id"` y leer la alerta (línea, CWE-78, fuente).
3. Ejecutar con `-v` para mostrar la ruta del dato.
4. Agregar `[[ $1 =~ ^[a-z]+$ ]] || exit 1` y mostrar cómo la alerta baja a MEDIA.
5. Mostrar `--mode=conservative`, `--export=json` y el código de salida.

## 8. Arquitectura (resumen)

```
src/analyzer            punto de entrada (verifica Bash >= 4.4)
src/lib/
  i18n.sh               mensajes es/en
  rules.sh              carga del catálogo (rules/sources.conf)
  log.sh                bitácora de la sesión
  parser.sh / sources.sh  detección estática de fuentes
  propagation.sh        motor de taint tracking (propagación, validación, sinks)
  monitor.sh            generación del monitor y ejecución bajo trap DEBUG
  report.sh             clasificación, filtros, ignore-rule, texto/JSON, código de salida
  cli.sh                opciones y flujo principal
build.sh                concatena todo en dist/analyzer (archivo único)
install.sh              instala/desinstala dist/analyzer
tests/                  suite automatizada (positivos, negativos, recursivo, equivalencia)
docs/                   documentación LaTeX del proyecto
```

Flujo: **CLI → monitor (ejecución real) → eventos → motor de propagación → filtro/ignore-rule → reporte (texto/TSV) → exportación JSON → bitácora → código de salida.**

## 9. Calidad y pruebas

```bash
./tests/run_tests.sh        # suite general: 82 correctas, 0 fallidas
./tests/verificacion.sh     # 36 pruebas de verificación de los casos de uso (P01-01 … P06-05)
ANALYZER=dist/analyzer ./tests/run_tests.sh   # versión empaquetada
```

- Pruebas de detección estática y dinámica con salidas esperadas, modos, códigos de salida, JSON, `ignore-rule`, recursividad, listas blancas, equivalencia con/sin monitor, empaquetado e instalación.
- `shellcheck` sin avisos; el código no invoca herramientas de red (RNF-01).

## 10. Limitaciones conocidas (conviene decirlas con honestidad)

- Solo se analizan los comandos que **realmente se ejecutan**; las ramas no tomadas no se observan.
- Las variables se identifican por nombre (sin ámbito por función).
- Los datos que viajan por tubería hacia `xargs` no se siguen.
- `ssh "$host"` con host contaminado pero sin comando remoto no genera alerta.
- `grep -q` y `[ ... ]` no se reconocen como validación (`[[ ]]` y `case` sí).
- `case` solo se reconoce en bloques multilínea, no anidados.
- Una directiva `ignore-rule` dentro de una cadena entrecomillada puede malinterpretarse.
- Rutas con variables no se verifican para el aviso de script secundario inexistente.
- Verificación en Bash 4.4 real, Arch Linux y WSL **pendiente**.

## 11. Mapa de la documentación del proyecto

| Documento | Contenido |
|---|---|
| `docs/SRS.tex` | Requisitos de software |
| `docs/CasosDeUsoConDiagramas.tex` | CU01–CU06 con tablas de pruebas P01–P06 |
| `docs/Arquitectura.tex` | Arquitectura del sistema |
| `docs/Entorno.tex` | Entorno de laboratorio |
| `docs/Iteracion1–5.tex` | Descripción de cada iteración |
| `docs/PlanDesarrollo.tex` | Plan, decisiones y riesgos |
| `docs/Pruebas.tex` | Plan y resultados de pruebas |
| `README.md` | Guía rápida del repositorio |
