# Zeek-demo

A docker-compose setup to demo Zeek.

This setup is plumbing together the upstream Zeek container image with
[Prometheus](https://prometheus.io/), [Loki](https://grafana.com/oss/loki/)
and [Grafana](https://grafana.com/grafana/).

Dashboards for [Zeek logs](https://docs.zeek.org/en/master/logs/index.html)
and Zeek metrics from the [telemetry framework](https://docs.zeek.org/en/master/frameworks/telemetry.html) are available in the Grafana instance by default.

For traffic replay, the idea is to replay GENEVE or VXLAN encapsulated
traffic towards 127.0.0.1 on the respective default port for these
tunnel protocols. docker-compose is setting up port forwarding so that the
traffic reaches the Zeek process.

In effect, Zeek sees the traffic the same as if it was running in an
[AWS traffic monitoring](https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-packet-formats.html)
 or the AWS GWLB environment.

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


# Sending Mirror Traffic

From easiest to more exotic. As mentioned above, essentially sending
VXLAN or GENEVE encapsulated mirror traffic towards the container.

## capture-fwd

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


## Kernel based VXLAN

The following works with a kernel vxlan device natively:
 * Configure a vxlan0 device that is externally managed with a default port that's different than 4789
 * Setup a [tunnel_key set](https://man7.org/linux/man-pages/man8/tc-tunnel_key.8.html)

    sudo ip link add vxlan0 type vxlan dstport 14789 external
    sudo ip link set vxlan0 up
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

### MTU

What seems important here is a larger MTU for the docker bridge, otherwise
we see messages. See docker-compose.yaml.

    11:28:37.022033 IP 172.24.0.1.41955 > 172.24.0.2.4789: VXLAN, flags [I] (0x08), vni 42424
    IP truncated-ip - 10 bytes missing! 139.178.84.217.443 > 192.168.0.107.58922: Flags [.], seq 6082:7490, ack 747, win 118, options [nop,nop,TS val 1704108423 ecr 2103894686], length 1408
    11:28:37.022200 IP 172.24.0.1.41955 > 172.24.0.2.4789: VXLAN, flags [I] (0x08), vni 42424
    IP truncated-ip - 10 bytes missing! 139.178.84.217.443 > 192.168.0.107.58922: Flags [.], seq 7490:8898, ack 747, win 118, options [nop,nop,TS val 1704108423 ecr 2103894686], length 1408

Also, increase the MTU of the vxlan0 device

    sudo ip link set vxlan0 mtu 9216


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


# Advanced Host Configuration

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
