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

The following instructions describe sending VXLAN encapsulated traffic
towards the container.

See the section about [host configuration](#advanced-host-configuration)
for a few tuning suggestions that can not happen within the container.

### capture-fwd

A small [gopacket](https://github.com/google/gopacket) based program is located
in the capture-fwd directory. This currently supports VXLAN or GENVE
encapsulation sending the packet a destination IP (default 127.0.0.1).

    $ cd capture-fwd/capture-fwd
    $ go build

    $ sudo ./capture-fwd -i $INTERFACE -encap vxlan -destIp 127.0.0.1 'ip or ip6'

Alternatively, it can read a pcap file and forward its content encapsulated
towards the container (or any other monitoring setup):

    $ sudo ./capture-fwd -r /path/to/traffic.pcap -encap vxlan -destIp 127.0.0.1

#### Mac OSX with colima

On Mac OSX when using colima as a replacement for Docker Desktop, UDP port
forwarding is [not functional](https://github.com/lima-vm/lima/issues/366).
As [workaround](https://github.com/rancher-sandbox/rancher-desktop/issues/1611#issuecomment-1176491158),
it is possible to add a route to the zeek container network via the VM to
the host side and use the zeek container IP directly as `-destIP` parameter.



### Linux VXLAN Device

The following works with the Linux vxlan device natively:

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



## Advanced Host Configuration

When using the `capture-fwd` provided in this repository to monitor a local
network interface, that interface should have offloading features disabled:

    sudo ethtool -K $INTERFACE gro off gso off tso off rx-gro-hw off

Further, due to how traffic is sent into the container via individual UDP
packets with a docker-proxy process between), it is advisable to increase
the default socket buffer sizes to avoid causing send/receive buffer errors:

    sudo sysctl -w net.core.rmem_max=$(( 32 * 1024 * 1024 ))
    sudo sysctl -w net.core.rmem_default=$(( 32 * 1024 * 1024 ))
    sudo sysctl -w net.core.wmem_max=$(( 32 * 1024 * 1024 ))
    sudo sysctl -w net.core.wmem_default=$(( 32 * 1024 * 1024 ))

For persisting these values across reboots, set them in sysctl.conf.

## Packet Reordering

It appears, *cough*, that [UDP packet reordering over lo](https://lore.kernel.org/netdev/e0f9fb60-b09c-30ad-0670-aa77cc3b2e12@gmail.com/)
is a thing on Linux due to [scaling techniques](https://www.kernel.org/doc/Documentation/networking/scaling.rst)
employed for the loopback and veth interfaces.

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
When using `-r` to read from a pcap.

### Enable Receive Packet Steering (RPS)

Unfortunately, this needs to be done on the host loopback interface *and*
inside the container. For the latter, we need to play tricks if we want
to continue running the zeek container in unprivileged mode.

For an 8 CPU system, set the following CPU mask in the for `rps_cpus`:

    $ echo ff > /sys/devices/virtual/net/lo/queues/rx-0/rps_cpus

This will choose a CPU for packet handling based on on the flow hash
rather than the CPU on which `capture-fwd` is running.

For eth0 within the container, use `nsenter` on the host system to
enter the mount and network namespace of the container, then set
`rps_cpu` of `eth0` after remounting `/sys` read-write.

    $ TARGET_PID=$(pgrep -f '^/udp-dropper 4789$')
    $ sudo nsenter -m -n -t $TARGET_PID
    $ mount -o remount,rw /sys
    $ echo ff > /sys/devices/virtual/net/eth0/queues/rx-0/rps_cpus
    $ mount -o remount,ro /sys
    # Ctrl+D to exit

In a Docker container, sysfs is mounted read-only when running unprivileged.
To change the setting, we temporarily mount as `rw` and reset it afterwards.

It can also make sense to increase the `netdev_max_backlog` value to avoid
softnet drops (see the Monitoring for Packet Drops section).

    $ sysctl -w net.core.netdev_max_backlog=10000

### Sending packets directly to the Zeek container IP

Sending directly to the container IP rather than through the `docker-proxy`
listening on the loopback interface also improves the reordering issue.
Concretely, fetch the IP of the zeek container, then pass it to `capture-fwd`:

    $ IP=$(docker-compose exec zeek ip addr show eth0 | sed -n 's,.*inet \([^/]*\)/.*$,\1,p')
    $ echo $P
    172.24.0.2
    $ ./capture-fwd -delay 0us -destIp $IP -destPort 4789 -r ./1mio-packets.pcap

A nice side-effect of this is that it removes the `docker-proxy`
that's using up quite a bit of CPU time.

### Running capture-fwd in system.slice

Putting the `capture-fwd` process into the `system.slice` cgroup where
`docker.service` and the `docker-proxy` process live removes the packet
reordering issue during replay at least on my system without `taskset` and
using the loopback inteface:

    $ systemd-run -t --same-dir --wait --system \
        bash -c 'while true ; do ./capture-fwd -delay 0us -r ./1mio-packets.pcap  ; echo "$(date) replayed" ; done'

Not sure why this is, might be something cgroup/scheduling just working
out most of the time when running like that.

## Monitoring for Packet Drops

There are quite a few places where packets may be dropped.

Verify that the UDP send and receive buffer error metrics are not increasing
in the following netstat output while running `capture-fwd`

    $ netstat -suna | grep errors
    116588212 packet receive errors
    116587168 receive buffer errors
    186 send buffer errors

Check the UDP socket receive queue of `docker-proxy`. A small queue is
acceptable, a large one is not.

    $ netstat -uan | grep 4789
    udp        0      0 172.24.0.1:39305        172.24.0.2:4789         ESTABLISHED 1411396/docker-prox
    udp     4608      0 127.0.0.1:14789         0.0.0.0:*                           1411396/docker-prox
    udp        0      0 172.24.0.1:56902        172.24.0.2:4789         ESTABLISHED 1411396/docker-prox
    ...

Verify the involved interfaces are not dropping:

    $ netstat --interfaces | grep -E 'Iface|veth|br-zeek' | column -t
    Iface     MTU   RX-OK  RX-ERR  RX-DRP  RX-OVR  TX-OK       TX-ERR  TX-DRP  TX-OVR  Flg
    br-zeekm  9216  3083   0       0       0       3369253302  0       0       0       BMRU
    ...
    vethb709  9216  127    0       0       0       274772936   0       1216    0       BMRU

Watch the `softnet_stat` stats whether the second column is increasing (drops)
indicating drops:

    $ watch -d -n 5 'cat /proc/net/softnet_stat'
    3ae12394 0000024b 00000000 00000000 00000000 00000000 00000000 00000000 00000000 018d2989 00000000 00000000 00000000
    459cafa9 000016b4 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0139b41c 00000000 00000000 00000001
    ...

Within the container, check the conn.log for connections with missed bytes:

    $ tail -F conn.log | jq -c  'select(.missed_bytes > 0)|[.missed_bytes, .service, .history, .missed_bytes, ."id.orig_h", ."id.orig_p", ."id.resp_h", ."tunnel_parents",.duration, .orig_ip_bytes, .resp_ip_bytes]'
    [470600,"ssl","ShADadtttttgFf",470600,"192.168.12.5",44070,"88.198.248.254",["CEvAIh2BkGzPol31vg"],0.9997329711914062,2094316,108334167]
    [10725336,"ssl","ShADadtttgttgFf",10725336,"192.168.12.5",35328,"88.198.248.254",["CEIxkj4VKssD6j2uCa"],0.9657478332519531,1763272,97712719]
    [15389344,"ssl","ShADadttttgFf",15389344,"192.168.12.5",35342,"88.198.248.254",["CitwcF39osaSu2ZSF2"],0.856626033782959,1148520,92879511]


Check metrics from Zeek process in container for dropped metrics:

    $ docker-compose exec zeek curl -s localhost:9911/metrics | grep packets_dropped
    # TYPE zeek_packets_dropped_total counter
    zeek_packets_dropped_total{endpoint=""} 0.000000 1673789010186
