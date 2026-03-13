FROM docker.io/grafana/loki:3.5

RUN mv /etc/loki/local-config.yaml /etc/loki/local-config.yaml.orig
COPY etc/loki/local-config.yaml /etc/loki/local-config.yaml
