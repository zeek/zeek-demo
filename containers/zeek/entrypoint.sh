#!/bin/bash
set -eux

INTERFACE=${INTERFACE:-eth0}

# Only analyze GENEVE or VXLAN encapsulated traffic
BPF_FILTER=${BPF_FILTER:-udp port (6081 or 4789)}

zeek --version

# Listen on UDP 4789 and UDP 6081 so that the container does
# not send out ICMP port unreachable responses for incoming
# mirrored traffic. We can probably have this cheaper with
# a custom daemon, but hey, this does it for now.
socat udp-recv:4789 /dev/null,ignoreeof &
socat udp-recv:6081 /dev/null,ignoreeof &

# TODO, Runs single process Zeek, no cluster.
exec zeek \
    -i "af_packet::${INTERFACE}" \
    --filter "${BPF_FILTER}" \
    --no-checksums \
    local
