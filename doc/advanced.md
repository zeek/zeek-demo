# Advanced Host Configuration

## Disable offloading features

When using the `capture-fwd` tool provided in this repository to monitor a
local network interface, that interface should have offloading features
disabled. The following works on Linux:

    sudo ethtool -K $INTERFACE gro off gso off tso off rx-gro-hw off

## Increase Socket Buffers

Due to how monitoring traffic is sent to the Zeek container as individual UDP
packets and a docker-proxy process between, it is advisable to increase the
default socket buffer sizes to avoid causing send/receive buffer errors.

On Linux, this can be done as follows:

    sudo sysctl -w net.core.rmem_max=$(( 32 * 1024 * 1024 ))
    sudo sysctl -w net.core.rmem_default=$(( 32 * 1024 * 1024 ))
    sudo sysctl -w net.core.wmem_max=$(( 32 * 1024 * 1024 ))
    sudo sysctl -w net.core.wmem_default=$(( 32 * 1024 * 1024 ))

For persisting these values across reboots, set them in sysctl.conf.

## Deal with Packet Reordering

It appears, *cough*, that [UDP packet reordering over loopback](https://lore.kernel.org/netdev/e0f9fb60-b09c-30ad-0670-aa77cc3b2e12@gmail.com/)
is a reality on Linux due to [scaling techniques employed](https://www.kernel.org/doc/Documentation/networking/scaling.rst)
for loopback and veth interfaces.

In the Zeek logs, this manifests as `missed_bytes` in the `conn.log`, while
the number of originator and responder packets is actually correct when
compared logs produced by a `zeek -r` invocation using a pcap file. Additionally,
the history shows gaps (gG) for such connections. This is, unfortunately,
a bit misleading as it's really just out-of-order packets rather than drops
or missed packets.

The most simple fix is to delay packets long enough so reordering is not
a problem. The `capture-fwd` utility has a `-delay` flag for delaying sending
of packets:

    $ sudo ./capture-fwd -delay 1ms -r test.pcap

Other than that, the approaches have been found as ways to alleviate
reordered packets on Linux specifically.

### CPU Pinning capture-fwd

The most straightforward and effective fix is using `taskset` to pin
`capture-fwd` to a single CPU:

    $ taskset -c 1 ./capture-fwd ./1mio-packets.pcap
    $ taskset -c 1 ./capture-fwd -i $INTERFACE

### Enable Receive Packet Steering (RPS)

A separate fix is to enable RPS on the loopback interface *and* the
veth used by the container. The former needs a privileged user on the host,
the latter needs to be done as a privileged user inside the container.
For the latter, the below instructions play a few tricks tricks so that
we can continue running the Zeek container itself unprivileged.

For an 8 CPU system, set the following CPU mask in the for `rps_cpus`
of the `lo` device:

    $ echo ff > /sys/devices/virtual/net/lo/queues/rx-0/rps_cpus

This will choose a CPU for packet handling based on on the flow hash
rather than selecting the CPU on which `capture-fwd` happens to run.

To configure RPS for the `eth0` device within the container, use `nsenter`
as root on the host system to enter the mount and network namespace of
the container, then set `rps_cpu` of `eth0` after remounting `/sys` read-write.

    $ TARGET_PID=$(pgrep -f '^/udp-dropper 4789$')
    $ sudo nsenter -m -n -t $TARGET_PID
    $ mount -o remount,rw /sys
    $ echo ff > /sys/devices/virtual/net/eth0/queues/rx-0/rps_cpus
    $ mount -o remount,ro /sys
    # Ctrl+D to exit

In a Docker container, sysfs is mounted read-only when running unprivileged.
To change the setting, the above script temporarily re-mounts /sysfs as `rw`
and reset it afterwards.

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

## Monitoring for Packet Drops

In this setup, there can be quite a few places where packets are dropped
or buffers run out of space.

### UDP Send and Receive Buffers

Verify that the UDP send and receive buffer error metrics are not increasing
in the following netstat output while running `capture-fwd`:

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

### Interface drops

Verify the involved interfaces are not dropping packets:

    $ netstat --interfaces | grep -E 'Iface|veth|br-zeek' | column -t
    Iface     MTU   RX-OK  RX-ERR  RX-DRP  RX-OVR  TX-OK       TX-ERR  TX-DRP  TX-OVR  Flg
    br-zeekm  9216  3083   0       0       0       3369253302  0       0       0       BMRU
    ...
    vethb709  9216  127    0       0       0       274772936   0       1216    0       BMRU

### Softnet stat drops

Watch `/proc/net/softnet_stat` whether the second column is increasing (drops).
This happens when there's no room on a given CPU to enqueue more packets.

    $ watch -d -n 5 'cat /proc/net/softnet_stat'
    3ae12394 0000024b 00000000 00000000 00000000 00000000 00000000 00000000 00000000 018d2989 00000000 00000000 00000000
    459cafa9 000016b4 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0139b41c 00000000 00000000 00000001
    ...

### Check for missed_bytes / gaps

Within the Zeek container, check the conn.log for connections with missed bytes
and gaps in the history.

    $ tail -F conn.log | jq -c  'select(.missed_bytes > 0)|[.missed_bytes, .service, .history, .missed_bytes, ."id.orig_h", ."id.orig_p", ."id.resp_h", ."tunnel_parents",.duration, .orig_ip_bytes, .resp_ip_bytes]'
    [470600,"ssl","ShADadtttttgFf",470600,"192.168.12.5",44070,"88.198.248.254",["CEvAIh2BkGzPol31vg"],0.9997329711914062,2094316,108334167]
    [10725336,"ssl","ShADadtttgttgFf",10725336,"192.168.12.5",35328,"88.198.248.254",["CEIxkj4VKssD6j2uCa"],0.9657478332519531,1763272,97712719]
    [15389344,"ssl","ShADadttttgFf",15389344,"192.168.12.5",35342,"88.198.248.254",["CitwcF39osaSu2ZSF2"],0.856626033782959,1148520,92879511]

Check the Prometheus metrics of the Zeek process in the Zeek container
for drops. These indicate Zeek isn't able to keep up processing packets
itself:

    $ docker-compose exec zeek curl -s localhost:9911/metrics | grep packets_dropped
    # TYPE zeek_packets_dropped_total counter
    zeek_packets_dropped_total{endpoint=""} 0.000000 1673789010186

## Alternative Mirroring Setups

### Linux VXLAN Device

Instead of using `capture-fwd`, an externally managed Linux vxlan device can
be configured as follows `tc` employed for sending mirror traffic towards
the Zeek container.

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
