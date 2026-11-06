# Laboratorio aislado para el analizador (modo dinamico EJECUTA los scripts analizados).
# Construir:  docker build -t bash-analyzer-lab .
# Ejecutar (ver README, seccion "Laboratorio con Docker"):
#   docker run -it --rm --network none --cap-drop ALL --security-opt no-new-privileges \
#     --tmpfs /tmp:rw,exec,nosuid --tmpfs /home/lab/.local:rw,exec,nosuid,uid=1000,gid=1000 bash-analyzer-lab
FROM debian:12-slim

# python3 solo se usa para validar el JSON en las pruebas; shellcheck para el analisis del codigo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash python3 shellcheck jq util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash lab

# Sin privilegios: los scripts analizados no corren como root dentro del contenedor.
USER lab
WORKDIR /home/lab/proyecto
COPY --chown=lab:lab . .

ENV ANALYZER_LOG_DIR=/home/lab/.local/state/bash-analyzer
CMD ["/bin/bash"]
