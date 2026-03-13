#!/bin/bash
set -eux

# Prep the Zeek configuration.
ZEEK_INTERFACE=${ZEEK_INTERFACE:-udp::0.0.0.0:4789:vxlan}
ZEEK_WORKERS=${ZEEK_WORKERS:-4}
ZEEK_PROXIES=${ZEEK_PROXIES:-2}
ZEEK_LOGGERS=${ZEEK_LOGGERS:-1}
ZEEK_METRICS_ADDRESS=${ZEEK_METRICS_ADDRESS:-0.0.0.0}

cat <<EOF > /usr/local/zeek/etc/zeek/zeek.conf
interface = ${ZEEK_INTERFACE}

workers = ${ZEEK_WORKERS}
loggers = ${ZEEK_LOGGERS}
proxies = ${ZEEK_PROXIES}

worker_memory_max = 512M
logger_memory_max = 512M
proxy_memory_max = 512M
manager_emory_max = 512M

metrics_address = ${ZEEK_METRICS_ADDRESS}
EOF

# Let systemd do the rest.
exec /sbin/init
