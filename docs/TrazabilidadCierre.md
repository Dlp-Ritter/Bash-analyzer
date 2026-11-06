# Matriz de trazabilidad de cierre

Esta matriz separa capacidades implementadas de afirmaciones que requieren una
medición experimental adicional. El modo dinámico ejecuta el script objetivo y
solo debe usarse en el laboratorio aislado.

| Requisito | Implementación | Evidencia automatizada | Estado |
|---|---|---|---|
| RF-01 | Parser heurístico y catálogo; detección estática de fuentes y construcciones observables | `tests/run_tests.sh`, pruebas `--static` | Parcial: no es un AST completo ni confirma flujos no ejecutados |
| RF-02 | `monitor.sh`, `propagation.sh`, propagación taint en comandos observables | pruebas dinámicas de propagación, funciones, sobrescritura y sanitización | Cumplido dentro de los límites documentados |
| RF-03 | Directiva `ignore-rule` en `report.sh` | P04-01…P04-06 | Cumplido |
| RF-04 | Herencia de `BASH_ENV` y seguimiento opcional con `--recursive` | P05-01…P05-05 | Cumplido dentro de los límites documentados |
| RF-05 | Reporte de línea, código, severidad, origen, sink y CWE | P01/P03 y pruebas de color | Cumplido |
| RF-06 | Modos `strict` y `conservative` | RF-06 y pruebas de salida | Cumplido |
| RF-07 | Exportación JSON y validación con `json.tool` | P06-01…P06-05 | Cumplido |
| RNF-01 | Procesamiento local; no se invocan herramientas de red | prueba RNF-01 | Cumplido por diseño y prueba de regresión |
| RNF-02 | Instrumentación mediante `trap DEBUG` | Suite funcional | Pendiente de benchmark formal; no se afirma sobrecarga imperceptible |
| RNF-03 | Script autónomo generado por `build.sh`, Bash 4.4+ | pruebas de empaquetado y dependencia | Bash 4.4 real, Arch y WSL deben verificarse en sus entornos |
| RNF-04 | Mensajes en español e inglés mediante `i18n.sh` | pruebas CLI de idioma | Cumplido |
| RNF-05 | Catálogo desacoplado en `rules/sources.conf` | pruebas de catálogo y empaquetado | Cumplido |

## Seguridad operacional

El análisis dinámico requiere confirmación. En una terminal interactiva se
solicita una respuesta afirmativa; en procesos sin terminal se debe proporcionar
`--yes` o `--allow-execution`. `--static` nunca ejecuta el objetivo. La variable
`ANALYZER_ALLOW_EXECUTION=1` se reserva para el laboratorio de pruebas.

## Terminología

`dist/analyzer` es un **script Bash autónomo de un solo archivo**, no un binario
nativo enlazado estáticamente. El análisis estático es heurístico y basado en
líneas; el monitor instrumenta comandos Bash observables mediante `trap DEBUG`.
Las referencias de los hallazgos son CWE. CVE y CVSS se reservan para
vulnerabilidades y evaluaciones externas concretas, respectivamente.
