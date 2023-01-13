FROM grafana/loki:2.7.1

RUN mv /etc/loki/local-config.yaml /etc/loki/local-config.yaml.orig
COPY etc/loki/local-config.yaml /etc/loki/local-config.yaml
