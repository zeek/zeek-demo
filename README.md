# Zeek-demo

A docker-compose to demo Zeek.

For traffic replay, the idea is to replay GENEVE or VXLAN encapsulated
traffic to 127.0.0.1 on the respective default port. docker-compose is
setting up port forwarding so that the traffic reaches the Zeek process.

In effect, Zeek sees the traffic the same as if it was running in an
AWS traffic monitoring or the GWLB environment.

Quick links:

    # Prometheus
    http://localhost:19090

    # Grafana (default zeek:zeek credentials)
    http://localhost:13000

    # VXLAN / Geneve ports forwarded into zeek container.
    127.0.0.1:4789/udp
    127.0.0.1:6081/udp


# Mirror VXLAN encapsulated traffic into container

## VXLAN

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


## GENEVE (not working with the tc tunnel_key action)

By default, the zeek service started by docker-compose is accessible
through port 6081 and Zeek's filter set to ``udp port 6081``.

    sudo ip link add name gnv0 type geneve id 1000 remote 127.0.0.1 dstport 16081
    sudo ip link set gnv0 up

    sudo tc qdisc add dev gnv0 root handle 1: prio
    sudo tc filter add dev gnv0 protocol ip parent 1:     matchall     action tunnel_key set     src_ip 127.0.0.2     dst_ip 127.0.0.3     dst_port 6081     id 42424     pass

    The dst_port isn't honored and is using 16081 instead. That seems to be
    a kernel bug (or missing functionality) in that dst_port is not respected
    for GENVE encapsulation.

## capture-fwd

A small gopacket based program is located in capture-fwd. This currently
allows VXLAN encapsulation and then sending the packet to the IP where
the sniffer is running.

There's also Corelight's [vxlan.py](https://github.com/corelight/container-monitoring/blob/main/monitoring/vxlan.py)
that does something similar with Python.


# Zeek setup

On the Zeek side, we're receiving VXLAN (or GENEVE) encapsulated traffic
this way.

* Use a BPF filter to only select 4789 and 6081 traffic.

TODO:
* Possibly use the skip analyzer to jump over the encapsulation.
* Use log policy to remove the VXLAN/GENEVE log entries if they
  don't have a tunnel.
* Remove `tunnel_parent`, too?

## Checksums oh my

The interface within the zeek container has rx/tx checksum offloading
enabled, meaning the packets seen via tcpdump within the container do
not have correct checksums on the outer layer.

Maybe the skip analyzer will help here, too.
