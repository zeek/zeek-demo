FROM grafana/grafana:9.3.2

USER root
RUN mv /etc/grafana/grafana.ini /etc/grafana/grafana.ini.orig
COPY etc/grafana/grafana.ini /etc/grafana/grafana.ini

COPY ./etc/grafana/provisioning/datasources /etc/grafana/provisioning/datasources
COPY ./etc/grafana/provisioning/dashboards /etc/grafana/provisioning/dashboards
COPY ./dashboards /var/lib/grafana/dashboards

# This is what upstream uses.
USER 482
