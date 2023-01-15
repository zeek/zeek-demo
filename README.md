# Zeek-demo

A docker-compose setup to demo [Zeek](https://github.com/zeek/zeek).

This setup is plumbing together the [official zeek/zeek-dev container image](https://hub.docker.com/r/zeek/zeek-dev)
with [Prometheus](https://prometheus.io/), [Loki](https://grafana.com/oss/loki/)
and [Grafana](https://grafana.com/grafana/).

Dashboards for [Zeek logs](https://docs.zeek.org/en/master/logs/index.html)
and Zeek metrics from the [telemetry framework](https://docs.zeek.org/en/master/frameworks/telemetry.html) are available in the Grafana instance by default.

For traffic replay, the idea is to send [GENEVE](https://www.rfc-editor.org/rfc/rfc8926.html)
or [VXLAN](https://www.rfc-editor.org/rfc/rfc7348.html) encapsulated traffic
towards 127.0.0.1 on the respective default port for these tunnel protocols.
The docker-compose configuration is setting up port forwarding such that the
traffic reaches the Zeek process.

In effect, when using VXLAN encapsulation, Zeek observes the traffic the same
as if it were deployed in an [AWS traffic monitoring](https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-packet-formats.html) environment.

## Running

Clone the repository and run docker-compose up.

    $ git clone https://github.com/zeek/zeek-demo
    $ cd zeek-demo
    $ docker-compose up

## Quick links

After starting running `up`, the following links should be reachable on
the host system.

    # Grafana (zeek:zeek as credentials)
    http://localhost:13000

    # Loki
    http://localhost:13100

    # Prometheus
    http://localhost:19090

    # VXLAN / Geneve ports forwarded into zeek container.
    127.0.0.1:4789/udp
    127.0.0.1:6081/udp


## Sending Mirror Traffic

From easiest to rather exotic. As mentioned above, essentially sending
VXLAN or GENEVE encapsulated mirror traffic towards the container.

See the section about [host configuration](#advanced-host-configuration)
for a few tuning suggestions that can not happen within the container.

### capture-fwd

A small [gopacket](https://github.com/google/gopacket) based program is located
in the capture-fwd directory. This currently supports VXLAN or GENVE
encapsulation sending the packet a destination IP (default 127.0.0.1).

    $ cd capture-fwd
    $ go build

    $ sudo ./capture-fwd -i $INTERFACE -encap vxlan -destIp 127.0.0.1 'ip or ip6'

Alternatively, it can read a pcap file and forward its content:

    $ sudo ./capture-fwd -r /path/to/traffic.pcap -encap vxlan -destIp 127.0.0.1 'ip or ip6'


There's also Corelight's [vxlan.py](https://github.com/corelight/container-monitoring/blob/main/monitoring/vxlan.py)
that does something similar in Python, but is quite specific to a setup within
Kubernetes.


### Kernel based VXLAN

The following works with a kernel vxlan device natively:

* Configure a vxlan0 device that is externally managed with a default port that's different than 4789
* Setup a [tunnel_key set](https://man7.org/linux/man-pages/man8/tc-tunnel_key.8.html)

    sudo ip link add vxlan0 type vxlan dstport 14789 external
    sudo ip link set vxlan0 up
    sudo ip link set vxlan0 mtu 9216

    sudo tc qdisc add dev vxlan0 root handle 1: prio
    sudo tc filter add dev vxlan0 protocol ip parent 1: \
       matchall \
       action tunnel_key set \
       src_ip 127.0.0.4 \
       dst_ip 127.0.0.1 \
       dst_port 4789 \
       id 42424 \
       pass

Send all traffic originating from 127.0.0.4 to 127.0.0.1:4789 using tunnel_key set.

At this point we can replay into vxlan0 using tcprelay and have transparent
vxlan encapsulation towards 127.0.0.1:4789 where Zeek will pick it up. We can
also mirror all traffic from another interface into vxlan0 to mirror it to
the container.

    tc qdisc add dev wlp0s20f3 root handle 1: prio
    tc qdisc add dev wlp0s20f3 handle ffff: ingress
    tc filter add dev wlp0s20f3 parent 1: matchall action mirred egress mirror dev vxlan0
    tc filter add dev wlp0s20f3 parent ffff: matchall action mirred egress mirror dev vxlan0



## Kernel based GENEVE (not working with the tc tunnel_key action)

By default, the zeek service started by docker-compose is accessible
through port 6081 and Zeek's filter set to ``udp port 6081``.

    sudo ip link add name gnv0 type geneve id 1000 remote 127.0.0.1 dstport 16081
    sudo ip link set gnv0 up

    sudo tc qdisc add dev gnv0 root handle 1: prio
    sudo tc filter add dev gnv0 protocol ip parent 1:     matchall     action tunnel_key set     src_ip 127.0.0.2     dst_ip 127.0.0.3     dst_port 6081     id 42424     pass

    The dst_port isn't honored and is using 16081 instead. That seems to be
    a kernel bug (or missing functionality) in that dst_port is not respected
    for GENVE encapsulation.


## Advanced Host Configuration

When using the `capture-fwd` provided in this repository to monitor a local
network interface, that interface should have offloading features disabled:

    sudo ethtool -K $INTERFACE gro off gso off tso off rx-gro-hw off

Further, due to how traffic is sent into the container via individual UDP
packets with a docker-proxy process between), it is advisable to increase
the default socket buffer sizes to avoid causing send/receive buffer errors:

    sudo sysctl -w net.core.rmem_max=26214400
    sudo sysctl -w net.core.rmem_default=26214400
    sudo sysctl -w net.core.wmem_max=26214400
    sudo sysctl -w net.core.wmem_default=26214400

For persisting these values across reboots, set them in sysctl.conf.

Verify that the send and receive buffer error metrics are not increasing
in the following netstat output while running `capture-fwd`

    $ netstat --stat --udp
    ...
    Udp:
        65749361 packets received
        3426141 packets to unknown port received
        4395289 packet receive errors
        66934818 packets sent
        4394245 receive buffer errors
        161 send buffer errors
        InCsumErrors: 1044
        IgnoredMulti: 14

Also, verify `capture-fwd` is able to collect and forward packets fast enough.

## Packet Reordering

It appears, *cough*, that [UDP packet reordering over lo](https://lore.kernel.org/netdev/e0f9fb60-b09c-30ad-0670-aa77cc3b2e12@gmail.com/)
is a thing on Linux due to [scaling techniques](https://www.kernel.org/doc/Documentation/networking/scaling.rst)
employed for the loopback interface.

In the Zeek logs, this manifests as `missed_bytes` in the `conn.log`, while
the number of originator and responder packets is the same as if the involved
pcap (when using `capture-fwd -r`) was fed into Zeek directly using `zeek -r`.
Further, the history shows gaps (gG) for such connections. This is, unfortunately,
a bit misleading as it's really out-of-order packets rather than gaps.

The following approaches have been found as ways to alleviate this:

### CPU Pinning capture-fwd to a single CPU with taskset

Running `capture-fwd` at high packet rates sending to the default
loopback address may be affected. The most straightforward and effective
fix appears running with `taskset` to pin `capture-fwd` to a single CPU:

    $ taskset -c 1 ./capture-fwd ./1mio-packets.pcap
    $ taskset -c 1 ./capture-fwd -i $INTERFACE

Alternatively, there's a `-delay` flag for delaying sending of packets.
When using `-r` to read from a pcap, this defaults to 1usec.

### Sending packets directly to the Zeek container IP

Sending directly to the container IP rather than through the `docker-proxy`
listening on the the loopback interface also improves the reordering issue
as well. Concretely, fetch the IP of the zeek container, then pass
it to `capture-fwd`

    $ IP=$(docker-compose exec zeek ip addr show eth0 | sed -n 's,.*inet \([^/]*\)/.*$,\1,p')
    $ echo $P
    172.24.0.2
    $ ./capture-fwd -delay 0us -destIp $IP -destPort 4789 -r ./1mio-packets.pcap

A nice side-effect of this is that it removes the `docker-proxy`
that's using up quite a bit of CPU time.

### Running capture-fwd in system.slice

Putting the `capture-fwd` process into the `system.slice` cgroup whereo
`docker.service` and the `docker-proxy` process live removes the packet
reordering issue during replay at least on my system without `taskset` and
using the loopback inteface:

    $ systemd-run -t --same-dir --wait --system \
        bash -c 'while true ; do ./capture-fwd -delay 0us -r ./1mio-packets.pcap  ; echo "$(date) replayed" ; done'

Not sure why this is..
