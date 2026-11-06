# Analizador Dinámico de Inyección de Comandos en Bash

Herramienta de línea de comandos (CLI), 100 % local y escrita en Bash puro, que combina análisis estático de scripts Bash con rastreo dinámico del flujo de datos (*taint tracking*) para detectar inyección de comandos (CWE-78).

> **Estado:** en desarrollo (Proyecto de Graduación II, Universidad Mariano Gálvez de Guatemala). Iteraciones 1 a 5 implementadas y empaquetado listo. La validación experimental de este cierre se realizó en Linux con Bash 5.2; Bash 4.4+ es el requisito de compatibilidad declarado.

> **Advertencia:** el análisis dinámico **ejecuta** el script con los privilegios del usuario. En terminal interactiva se solicita confirmación; en automatizaciones se debe usar explícitamente `--yes` o `--allow-execution`. Para inspeccionar sin ejecutar, usa `--static`. El analizador no es un sandbox: usa una VM o contenedor para scripts no confiables.

## Qué hace

1. Identifica **fuentes** de datos externos: `$1..$N`, variables de entorno, `stdin`/`read`, lectura de archivos y salida de comandos.
2. Rastrea cómo se **propagan** esos datos entre variables, funciones y archivos mientras el script se ejecuta.
3. Detecta cuando llegan a un **punto sensible**: `eval`, subprocesos (`bash -c`, `sh -c`...), `source`, comandos elegidos por el dato (`$cmd`, `sudo`, `exec`, `xargs`, `env`...), comandos remotos de `ssh` y variables sin comillas.
4. Emite **alertas** con archivo, línea, severidad, ruta del dato, CWE y explicación; exporta a JSON.

El modo estático realiza una preevaluación heurística de fuentes y sinks potenciales sin ejecutar el script. El modo dinámico confirma los flujos observados durante la ejecución. Esta herramienta es complementaria a ShellCheck: ShellCheck cubre sintaxis, estilo y advertencias generales de Bash; este analizador se centra en el recorrido de datos externos hacia operaciones sensibles.

## Requisitos

- Linux; la validación experimental de este cierre se realizó en el laboratorio Linux con Bash 5.2.
- Bash 4.4+ o 5.x como requisito declarado.
- Sin dependencias de instalación ni conexión a internet. No envía telemetría.

## Instalación

Se distribuye como un único script generado desde las fuentes:

```bash
./install.sh                       # genera dist/analyzer e instala en ~/.local/bin (o /usr/local/bin si eres root)
./install.sh --prefix=/opt/az      # otro destino: /opt/az/bin/analyzer
./install.sh --uninstall           # desinstala
analyzer --version
```

También se puede generar el archivo con `./build.sh` y copiar `dist/analyzer` a cualquier directorio del `PATH`. Durante el desarrollo se puede usar `src/analyzer` directamente.

El archivo generado es autónomo: incluye los módulos y el catálogo de reglas, y solo necesita Bash 4.4+ y los comandos `cat`, `cmp`, `date`, `env`, `mkdir`, `mktemp`, `rm`, `sed` y `tr`. Si falta alguno, o si Bash es anterior a 4.4, termina con código 2 y un mensaje claro.

## Uso

```bash
analyzer script.sh [argumentos del script...]   # análisis dinámico (modo strict)
analyzer --mode=conservative script.sh arg      # solo severidades crítica y alta
analyzer -r script.sh arg                       # incluye scripts invocados (source, bash otro.sh)
analyzer -v script.sh arg                       # agrega la ruta completa y las etapas intermedias
analyzer --static script.sh                     # solo análisis estático: NO ejecuta el script
analyzer --yes script.sh arg                    # confirma explícitamente la ejecución dinámica
analyzer --export=json salida.json script.sh arg
analyzer --format=tsv script.sh arg             # eventos en TSV (para pruebas)
analyzer --help                                 # ayuda rápida
analyzer --manual                               # manual completo en terminal
```

El primer argumento que no es una opción es el script; todo lo que sigue se le pasa tal cual. La salida del script analizado va a la salida de error del analizador; el reporte va a la salida estándar.

| Parámetro | Descripción | Por defecto |
|---|---|---|
| `--mode=strict\|conservative` | `strict` reporta todo; `conservative` solo severidad crítica y alta | `strict` |
| `-r`, `--recursive` | Analiza scripts secundarios (`source`, `.`, `bash otro.sh`) | desactivado |
| `-v`, `--verbose` | Ruta completa del dato y etapas intermedias | desactivado |
| `--export=json <archivo>` | Exporta los hallazgos a JSON | desactivado |
| `--static` | Solo análisis estático, sin ejecutar el script | desactivado |
| `--yes`, `--allow-execution` | Confirma la ejecución dinámica; necesario en automatizaciones sin terminal | desactivado |
| `--format=text\|tsv` | Formato de salida | `text` |
| `-q`, `--quiet` | Sin avisos informativos | desactivado |
| `--no-script-output` | Descarta la salida del script analizado | desactivado |
| `--lang=es\|en` | Idioma de la interfaz | `es` |

### Severidades

| Severidad | Hallazgo | CWE |
|---|---|---|
| Crítica | Dato externo en `eval` o en `<shell> -c` (también tras `sudo`, `env`, etc.) | CWE-78 |
| Crítica | El dato decide qué comando se ejecuta (`$cmd`, `sudo "$x"`, `exec "$x"`, `xargs "$x"`) | CWE-78 |
| Crítica | El dato forma parte del comando remoto de `ssh host "$x"` | CWE-78 |
| Crítica | `source "$x"` / `. "$x"` con ruta controlada por el dato | CWE-94 |
| Alta | Variable contaminada sin comillas | CWE-88 |
| Media | Dato saneado con `printf '%q'` o validado con lista blanca que llega a un punto sensible; dato contaminado sin comillas en `echo`/`printf` | CWE-20 |
| Informativa | Variable sin comillas sin dato externo | — |

### Omitir una regla

```bash
# ignore-rule
eval "$comando_validado"

eval "$x"   # ignore-rule:EVAL
```

Sin identificador excluye todas las alertas de la línea; con identificador (`EVAL`, `SUBSHELL`, `EXECCMD`, `SOURCEFILE`, `SSHCMD`, `UNQUOTED`, `SANITIZED`, `LOWRISK`, `CONSTANT`, separados por coma) excluye solo ese tipo. El reporte indica cuántas líneas se excluyeron.

### Ejemplo de alerta

```
  [CRITICA] script.sh:5  eval con dato externo (CWE-78)
    Codigo:          > eval "$comando"
    Fuente:          $1
    Punto sensible:  eval
    Referencia:      CWE-78
    Explicacion:     eval interpreta el dato como codigo Bash: quien controle la entrada puede ejecutar comandos arbitrarios.
```

Con `-v` se agrega `Ruta: $1 -> entrada -> comando -> eval`.

### Código de salida

| Código | Significado |
|---|---|
| 0 | Análisis terminado sin alertas críticas (o en modo `conservative`) |
| 1 | Modo `strict` con al menos una alerta crítica |
| 2 | Error de uso o de archivo |

### Análisis recursivo

Con `-r`, los `source` se analizan en el mismo proceso (el dato contaminado fluye entre archivos) y los `bash otro.sh` en un proceso hijo con el mismo monitor. El reporte indica el origen de cada hallazgo. Si un script secundario con ruta literal no existe, avisa y continúa.

## Limitaciones conocidas

- El modo estático usa heurísticas léxicas y puede producir indicadores potenciales; la confirmación del flujo requiere el modo dinámico.
- Solo se analizan los comandos que realmente se ejecutan (una rama que no corre no genera eventos).
- La instrumentación dinámica mediante `trap DEBUG` añade sobrecarga, especialmente en scripts con muchos comandos o bucles intensivos.
- Si el script modifica o desactiva `trap DEBUG`, la cobertura dinámica puede ser parcial.
- Las variables se identifican por nombre, sin distinguir ámbitos de funciones.
- Saneamiento reconocido: `printf '%q'` y la validación con `[[ $x =~ ^regex-acotada$ ]]` o `[[ $x == "literal" ]]` (también negadas con `!` o `!=`). Una regex laxa (`^.*$`), sin anclas o con clases que admiten `;`, `$`, comillas o espacios no cuenta. También `case "$x" in lit1|lit2) ... ;; *) exit 1 ;; esac` (bloques multilínea; patrones con `*` o `?` no cuentan). `grep -q` y `[ ... ]` aún no se reconocen.
- Los datos que llegan por tubería a `xargs` (`echo "$x" | xargs ...`) no se siguen, y un `ssh "$host"` con el host contaminado pero sin comando no genera alerta.
- Las rutas de scripts secundarios con variables o sustituciones no se comprueban para el aviso de ruta inexistente.

## Estructura del repositorio

```
src/analyzer        punto de entrada de desarrollo
install.sh          instala o desinstala dist/analyzer
src/lib/            módulos: i18n, rules, log, parser, sources, propagation, monitor, report, cli
rules/              catálogo de fuentes, reglas, severidades y CWE (sources.conf)
tests/              positivos/, negativos/, recursivo/, expected/, expected_dyn/, run_tests.sh
build.sh            genera dist/analyzer (archivo único)
logs/               bitácoras generadas en pruebas
docs/               SRS, casos de uso, arquitectura, iteraciones, pruebas y plan de desarrollo
```

## Pruebas

Ejecutar **solo** dentro del entorno aislado (VM o contenedor), porque las pruebas dinámicas ejecutan scripts:

```bash
./tests/run_tests.sh                       # prueba src/analyzer
ANALYZER=dist/analyzer ./tests/run_tests.sh  # prueba la versión empaquetada
```

Los casos T01–T08, sus variantes y las pruebas de `ignore-rule` y del modo recursivo están descritos en `docs/Pruebas.tex`. Los *payloads* son simulados; no probar contra sistemas de terceros.

## Documentación

La ayuda rápida está disponible con `analyzer --help` y el manual completo puede consultarse desde la terminal con `analyzer --manual`. La versión formal en LaTeX está en `docs/manual de usuario.tex`; la copia de texto plano utilizada por la CLI está en `docs/manual de usuario.txt`.

SRS, casos de uso, arquitectura, guía de entorno, iteraciones 1–5, pruebas y plan de desarrollo en `docs/`.

## Autor

Duglas Leonel Pop Guitz, Facultad de Ingeniería en Sistemas de Información, Universidad Mariano Gálvez de Guatemala.

## Verificación de casos de uso

`./tests/verificacion.sh` ejecuta las 36 pruebas P01-01 … P06-05 de los casos de uso (CU01–CU06).

## Laboratorio con Docker

El modo dinámico **ejecuta** el script analizado. Para probarlo con aislamiento:

```bash
docker build -t bash-analyzer-lab .

# Laboratorio aislado: sin red, sin privilegios, usuario no root
docker run -it --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,exec,nosuid --tmpfs /home/lab/.local:rw,exec,nosuid,uid=1000,gid=1000 bash-analyzer-lab
```

Dentro del contenedor (el proyecto está en `~/proyecto`, copiado, no montado):

```bash
./tests/run_tests.sh
./tests/verificacion.sh
./src/analyzer --export=json /tmp/salida.json mi_script.sh arg1 < /dev/null
```

- Para analizar tus propios scripts, cópialos con `docker cp mi_script.sh <contenedor>:/home/lab/proyecto/` o móntalos **en solo lectura**: `-v "$PWD/scripts":/scripts:ro`.
- Para sacar un JSON: `docker cp <contenedor>:/tmp/salida.json .` (sin `--rm`) o monta una carpeta de salida: `-v "$PWD/out":/out` y usa `--export=json /out/salida.json`.
- No uses `--read-only` en la imagen completa si vas a ejecutar `install.sh` o `build.sh` (escriben `dist/`).
- `/tmp` debe montarse con `exec` (las pruebas de empaquetado e instalación ejecutan copias del analizador desde allí); Docker monta los `tmpfs` con `noexec` por defecto.
- Ejecuta las dos suites por separado: `./tests/run_tests.sh; ./tests/verificacion.sh` (con `&&`, un fallo de la primera impide correr la segunda).
- Incluye `python3` (validación del JSON), `shellcheck` y `jq`.
