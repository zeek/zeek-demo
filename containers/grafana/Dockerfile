FROM docker.io/grafana/grafana:12.3

USER root
RUN mv /etc/grafana/grafana.ini /etc/grafana/grafana.ini.orig
COPY etc/grafana/grafana.ini /etc/grafana/grafana.ini

COPY ./etc/grafana/provisioning/datasources /etc/grafana/provisioning/datasources
COPY ./etc/grafana/provisioning/dashboards /etc/grafana/provisioning/dashboards
COPY ./dashboards /var/lib/grafana/dashboards

# This is what upstream uses.
USER 482
