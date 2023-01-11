#!/bin/bash
set -eux

INTERFACE=${INTERFACE:-eth0}

# Only analyze GENEVE or VXLAN encapsulated traffic
BPF_FILTER=${BPF_FILTER:-udp port (6081 or 4789)}

zeek --version

# TODO, Runs single process Zeek, no cluster.
exec zeek \
    -i "af_packet::${INTERFACE}" \
    --filter "${BPF_FILTER}" \
    --no-checksums \
    local
