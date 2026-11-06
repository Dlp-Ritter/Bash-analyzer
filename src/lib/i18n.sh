# i18n.sh - mensajes de la interfaz (español por defecto, inglés configurable)

ANALYZER_LANG="${ANALYZER_LANG:-es}"
declare -gA MSG_ES=() MSG_EN=()

MSG_ES[usage]='Uso: analyzer [opciones] <script.sh> [argumentos del script...]

Opciones:
  -h, --help               Muestra esta ayuda rapida
      --manual             Muestra el manual completo en la terminal
  -V, --version            Muestra la version
      --lang=es|en         Idioma de la interfaz (por defecto: es)
      --mode=strict|conservative
                           Rigurosidad de las alertas (por defecto: strict)
  -r, --recursive          Analiza tambien los scripts secundarios (source, bash x.sh)
  -v, --verbose            Agrega la ruta completa y las etapas intermedias
      --export=json <arch> Exporta los hallazgos a un archivo JSON
      --format=text|tsv    Formato de salida de las etapas disponibles
      --static             Solo analisis estatico (no ejecuta el script)
       --yes, --allow-execution
                            Confirma explicitamente la ejecucion dinamica
  -q, --quiet              Sin avisos informativos
      --no-script-output   Descarta la salida del script analizado

Por defecto el script SE EJECUTA bajo monitoreo (usar solo en un entorno
aislado). Codigo de salida: 0 correcto; 1 hay alertas CRITICAS (solo modo strict);
2 error de uso o de archivo.'
MSG_EN[usage]='Usage: analyzer [options] <script.sh> [script arguments...]

Options:
  -h, --help               Show this quick help
      --manual             Show the complete manual in the terminal
  -V, --version            Show version
      --lang=es|en         Interface language (default: es)
      --mode=strict|conservative
                           Alert strictness (default: strict)
  -r, --recursive          Also analyze secondary scripts (source, bash x.sh)
  -v, --verbose            Adds the full path and intermediate stages
      --export=json <file> Export findings to a JSON file
      --format=text|tsv    Output format for the available stages
      --static             Static analysis only (does not run the script)
       --yes, --allow-execution
                            Explicitly confirm dynamic execution
  -q, --quiet              No informational warnings
      --no-script-output   Discard the analyzed script output

By default the script IS EXECUTED under monitoring (use only in an isolated
environment). Exit status: 0 ok; 1 CRITICAL alerts found (strict mode only);
2 usage or file error.'

MSG_ES[title]='Analizador de inyeccion de comandos en Bash'
MSG_EN[title]='Bash command injection analyzer'
MSG_ES[file]='Archivo'
MSG_EN[file]='File'
MSG_ES[found]='Fuentes externas identificadas: %d'
MSG_EN[found]='External sources identified: %d'
MSG_ES[none]='No se identificaron fuentes externas segun el catalogo de reglas.'
MSG_EN[none]='No external sources were identified according to the rule catalog.'
MSG_ES[summary]='Resumen por tipo:'
MSG_EN[summary]='Summary by type:'
MSG_ES[err_no_file]='Error: el archivo "%s" no existe.'
MSG_EN[err_no_file]='Error: file "%s" does not exist.'
MSG_ES[err_not_readable]='Error: no se puede leer "%s".'
MSG_EN[err_not_readable]='Error: cannot read "%s".'
MSG_ES[err_not_bash]='Error: "%s" no parece un script Bash.'
MSG_EN[err_not_bash]='Error: "%s" does not look like a Bash script.'
MSG_ES[err_missing_file]='Error: falta indicar el script a analizar.'
MSG_EN[err_missing_file]='Error: no script to analyze was given.'
MSG_ES[err_unknown_opt]='Error: opcion desconocida "%s".'
MSG_EN[err_unknown_opt]='Error: unknown option "%s".'
MSG_ES[err_bad_value]='Error: valor no valido "%s" para %s.'
MSG_EN[err_bad_value]='Error: invalid value "%s" for %s.'
MSG_ES[err_no_rules]='Error: no se encontro el catalogo de reglas.'
MSG_EN[err_no_rules]='Error: rule catalog not found.'
MSG_ES[err_manual_missing]='Error: no se encontro el manual de usuario.'
MSG_EN[err_manual_missing]='Error: user manual not found.'
MSG_ES[warn_not_impl]='Aviso: la opcion %s se habilita en una iteracion posterior; se ignora por ahora.'
MSG_EN[warn_not_impl]='Warning: option %s is enabled in a later iteration; ignored for now.'

MSG_ES[warn_exec]='Aviso: el modo dinamico EJECUTA el script analizado. Use solo un entorno aislado (o --static).'
MSG_EN[warn_exec]='Warning: dynamic mode EXECUTES the analyzed script. Use only an isolated environment (or --static).'
MSG_ES[warn_exec_confirm]='Advertencia: el modo dinamico ejecutara el script con sus privilegios actuales.'
MSG_EN[warn_exec_confirm]='Warning: dynamic mode will execute the script with your current privileges.'
MSG_ES[confirm_exec]='Continuar? [s/N]'
MSG_EN[confirm_exec]='Continue? [y/N]'
MSG_ES[err_exec_confirmation]='Error: el modo dinamico requiere confirmacion interactiva; use --yes/--allow-execution o --static.'
MSG_EN[err_exec_confirmation]='Error: dynamic mode requires interactive confirmation; use --yes/--allow-execution or --static.'
MSG_ES[err_exec_cancelled]='Analisis dinamico cancelado por el usuario.'
MSG_EN[err_exec_cancelled]='Dynamic analysis cancelled by the user.'
MSG_ES[script_rc]='El script termino con codigo de salida %d.'
MSG_EN[script_rc]='The script exited with status %d.'
MSG_ES[hdr_src]='Fuentes externas observadas:'
MSG_EN[hdr_src]='External sources observed:'
MSG_ES[hdr_prop]='Propagacion de datos contaminados:'
MSG_EN[hdr_prop]='Tainted data propagation:'
MSG_ES[hdr_use]='Usos de datos contaminados:'
MSG_EN[hdr_use]='Uses of tainted data:'
MSG_ES[hdr_untaint]='Variables limpiadas:'
MSG_EN[hdr_untaint]='Variables cleaned:'
MSG_ES[mode_dyn]='Modo: dinamico (ejecucion real)'
MSG_EN[mode_dyn]='Mode: dynamic (real execution)'
MSG_ES[mode_static]='Modo: estatico (heuristico; no ejecuta el script)'
MSG_EN[mode_static]='Mode: static (heuristic; script is not executed)'
MSG_ES[hdr_static]='Indicadores estaticos:'
MSG_EN[hdr_static]='Static indicators:'
MSG_ES[static_note]='Estos indicadores son heuristicas; la confirmacion del flujo fuente-sink requiere el modo dinamico.'
MSG_EN[static_note]='These indicators are heuristics; source-to-sink confirmation requires dynamic mode.'
MSG_ES[static_confidence]='media'
MSG_EN[static_confidence]='medium'
MSG_ES[warn_debug_trap]='Aviso: el script modifica o desactiva trap DEBUG; la cobertura dinamica puede ser parcial.'
MSG_EN[warn_debug_trap]='Warning: the script modifies or disables trap DEBUG; dynamic coverage may be partial.'

MSG_ES[alerts_found]='Alertas generadas: %d'
MSG_EN[alerts_found]='Alerts generated: %d'
MSG_ES[no_alerts]='No se generaron alertas: ningun dato contaminado llego a un punto sensible.'
MSG_EN[no_alerts]='No alerts: no tainted data reached a sensitive sink.'
MSG_ES[hdr_alert]='Alertas:'
MSG_EN[hdr_alert]='Alerts:'
MSG_ES[sev_CRITICAL]='CRITICA'
MSG_EN[sev_CRITICAL]='CRITICAL'
MSG_ES[sev_HIGH]='ALTA'
MSG_EN[sev_HIGH]='HIGH'
MSG_ES[sev_MEDIUM]='MEDIA'
MSG_EN[sev_MEDIUM]='MEDIUM'
MSG_ES[lbl_source]='Fuente'
MSG_EN[lbl_source]='Source'
MSG_ES[lbl_path]='Ruta'
MSG_EN[lbl_path]='Path'
MSG_ES[lbl_confidence]='Confianza'
MSG_EN[lbl_confidence]='Confidence'
MSG_ES[lbl_sink]='Punto sensible'
MSG_EN[lbl_sink]='Sensitive sink'
MSG_ES[lbl_expl]='Explicacion'
MSG_EN[lbl_expl]='Explanation'
MSG_ES[lbl_note]='Nota'
MSG_EN[lbl_note]='Note'
MSG_ES[expl_EVAL]='eval interpreta el dato como codigo Bash: quien controle la entrada puede ejecutar comandos arbitrarios.'
MSG_EN[expl_EVAL]='eval interprets the data as Bash code: whoever controls the input can run arbitrary commands.'
MSG_ES[expl_SUBSHELL]='El dato se pasa como programa a un shell hijo (-c) sin validacion previa: permite inyectar comandos.'
MSG_EN[expl_SUBSHELL]='The data is passed as a program to a child shell (-c) without prior validation: it allows command injection.'
MSG_ES[expl_UNQUOTED]='La variable sin comillas se divide en palabras y expande comodines: el dato puede agregar opciones o argumentos al comando.'
MSG_EN[expl_UNQUOTED]='The unquoted variable is word-split and glob-expanded: the data can add options or arguments to the command.'

MSG_ES[sev_INFO]='INFORMATIVA'
MSG_EN[sev_INFO]='INFO'
MSG_ES[expl_SANITIZED]='El dato fue saneado (printf %%q) o validado con una lista blanca, pero el modo strict no lo considera suficiente: confirme que la validacion es adecuada para este contexto.'
MSG_EN[expl_SANITIZED]='The data was sanitized (printf %%q) or checked against a whitelist, but strict mode does not treat it as sufficient: confirm the validation is adequate for this context.'
MSG_ES[expl_LOWRISK]='Dato contaminado sin comillas en un comando que solo imprime: bajo riesgo, pero sigue habiendo word splitting y expansion de comodines.'
MSG_EN[expl_LOWRISK]='Tainted data without quotes in a print-only command: low risk, but word splitting and globbing still apply.'
MSG_ES[expl_CONSTANT]='Patron inseguro sin dato externo asociado: la variable sin comillas podria causar problemas si su valor cambia.'
MSG_EN[expl_CONSTANT]='Unsafe pattern without associated external data: the unquoted variable could cause problems if its value changes.'
MSG_ES[lbl_code]='Codigo'
MSG_EN[lbl_code]='Code'
MSG_ES[lbl_ref]='Referencia'
MSG_EN[lbl_ref]='Reference'
MSG_ES[lbl_none]='(sin dato externo)'
MSG_EN[lbl_none]='(no external data)'
MSG_ES[sev_summary]='Resumen por severidad:'
MSG_EN[sev_summary]='Summary by severity:'
MSG_ES[export_ok]='Hallazgos exportados a %s'
MSG_EN[export_ok]='Findings exported to %s'
MSG_ES[err_export]='Aviso: no se pudo escribir el archivo JSON "%s"; el analisis continua.'
MSG_EN[err_export]='Warning: could not write JSON file "%s"; analysis continues.'
MSG_ES[err_export_missing]='Error: --export=json requiere indicar el archivo de salida.'
MSG_EN[err_export_missing]='Error: --export=json requires an output file.'
MSG_ES[warn_export_static]='Aviso: --export solo aplica al modo dinamico; se ignora con --static.'
MSG_EN[warn_export_static]='Warning: --export only applies to dynamic mode; ignored with --static.'

MSG_ES[excluded_lines]='Lineas excluidas por directiva ignore-rule: %d'
MSG_EN[excluded_lines]='Lines excluded by ignore-rule directive: %d'
MSG_ES[files_analyzed]='Scripts analizados: %d (1 principal, %d secundarios)'
MSG_EN[files_analyzed]='Scripts analyzed: %d (1 main, %d secondary)'
MSG_ES[hdr_warn]='Avisos:'
MSG_EN[hdr_warn]='Warnings:'
MSG_ES[warn_unresolved]='Aviso: no se encontro el script secundario "%s" (%s:%s); se omite y el analisis continua.'
MSG_EN[warn_unresolved]='Warning: secondary script "%s" was not found (%s:%s); skipped, analysis continues.'
MSG_ES[lbl_origin]='Origen'
MSG_EN[lbl_origin]='Origin'
MSG_ES[origin_main]='script principal'
MSG_EN[origin_main]='main script'
MSG_ES[origin_sec]='script secundario'
MSG_EN[origin_sec]='secondary script'
MSG_ES[warn_recursive_static]='Aviso: -r solo aplica al modo dinamico; se ignora con --static.'
MSG_EN[warn_recursive_static]='Warning: -r only applies to dynamic mode; ignored with --static.'

MSG_ES[err_missing_cmd]='Error: falta el comando requerido "%s".'
MSG_EN[err_missing_cmd]='Error: required command "%s" is missing.'

MSG_ES[expl_EXECCMD]='El dato decide que programa se ejecuta (directamente o mediante sudo, exec, xargs, env...): permite ejecutar comandos arbitrarios.'
MSG_EN[expl_EXECCMD]='The data decides which program runs (directly or via sudo, exec, xargs, env...): it allows arbitrary command execution.'
MSG_ES[expl_SOURCEFILE]='source/. carga y ejecuta el archivo indicado por el dato: permite ejecutar codigo arbitrario.'
MSG_EN[expl_SOURCEFILE]='source/. loads and runs the file chosen by the data: it allows arbitrary code execution.'
MSG_ES[expl_SSHCMD]='El dato forma parte del comando que ssh ejecuta en el equipo remoto: permite inyectar comandos alli.'
MSG_EN[expl_SSHCMD]='The data is part of the command ssh runs on the remote host: it allows command injection there.'
MSG_ES[lbl_recommendation]='Recomendacion'
MSG_EN[lbl_recommendation]='Recommendation'
MSG_ES[rec_EVAL]='Evite eval; use arreglos o una lista blanca de operaciones permitidas.'
MSG_EN[rec_EVAL]='Avoid eval; use arrays or a whitelist of permitted operations.'
MSG_ES[rec_SUBSHELL]='Evite pasar datos externos a bash -c/sh -c; use una interfaz de argumentos segura.'
MSG_EN[rec_SUBSHELL]='Avoid passing external data to bash -c/sh -c; use a safe argument interface.'
MSG_ES[rec_UNQUOTED]='Entrecomille la expansion como "$variable" y use -- cuando corresponda.'
MSG_EN[rec_UNQUOTED]='Quote the expansion as "$variable" and use -- where appropriate.'
MSG_ES[rec_EXECCMD]='Use una lista blanca de comandos y argumentos permitidos.'
MSG_EN[rec_EXECCMD]='Use a whitelist of permitted commands and arguments.'
MSG_ES[rec_SOURCEFILE]='No cargue rutas controladas por el usuario; restrinja el directorio permitido.'
MSG_EN[rec_SOURCEFILE]='Do not source user-controlled paths; restrict the allowed directory.'
MSG_ES[rec_SSHCMD]='Separe y valide host, comando y argumentos antes de usar ssh.'
MSG_EN[rec_SSHCMD]='Separate and validate host, command, and arguments before using ssh.'

# msg <clave> [args...]  -> imprime el mensaje formateado (sin salto de linea)
msg() {
  local key=$1 t
  shift
  if [[ $ANALYZER_LANG == en ]]; then t=${MSG_EN[$key]-}; else t=${MSG_ES[$key]-}; fi
  [[ -z $t ]] && t=${MSG_ES[$key]-$key}
  # shellcheck disable=SC2059
  printf -- "$t" "$@"
}
msgln() { msg "$@"; printf '\n'; }
