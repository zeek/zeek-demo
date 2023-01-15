#!/bin/bash
set -eux

# Listen on UDP 4789 and UDP 6081 so that the container does
# not send out ICMP port unreachable responses for incoming
# mirrored traffic. Drop the packets in user-space.
/udp-dropper 4789 &
/udp-dropper 6081 &

# promtail startup
promtail -config.file /etc/promtail/config.yml &

# Zeek setup
INTERFACE=${INTERFACE:-eth0}

# Only analyze GENEVE or VXLAN encapsulated traffic
BPF_FILTER=${BPF_FILTER:-udp port (6081 or 4789)}

zeek --version
exec zeek \
    -i "af_packet::${INTERFACE}" \
    --filter "${BPF_FILTER}" \
    --no-checksums \
    local
