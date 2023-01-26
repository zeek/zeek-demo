# Zeek-demo

A docker-compose setup to demo [Zeek](https://github.com/zeek/zeek), plumbing
together the [official zeek/zeek-dev container image](https://hub.docker.com/r/zeek/zeek-dev),
[Prometheus](https://prometheus.io/), [Loki](https://grafana.com/oss/loki/)
and [Grafana](https://grafana.com/grafana/).

Dashboards for [Zeek logs](https://docs.zeek.org/en/master/logs/index.html)
and Zeek metrics from the [telemetry framework](https://docs.zeek.org/en/master/frameworks/telemetry.html)
are available in the Grafana instance by default.

For traffic replay, the idea is to send
[VXLAN](https://www.rfc-editor.org/rfc/rfc7348.html) or
[GENEVE](https://www.rfc-editor.org/rfc/rfc8926.html)
encapsulated traffic towards 127.0.0.1 on the respective default port of
these tunnel protocols. docker-compose configures port forwarding such that
the traffic reaches the Zeek process. In effect, when using VXLAN
encapsulation, Zeek observes the traffic the same as if it were deployed in an
[AWS traffic monitoring](https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-packet-formats.html) environment.

> **NOTE:** MacOS X with colima does not support UDP forwarding to
> containers, [see below for a workaround](#mac-os-x-with-colima).

To forward packets captured from local interfaces or replay a pcap, this
repository contains a tool called [capture-fwd](#capture-fwd).
See below for more details.

## Running

Clone the repository and run docker-compose up.

    $ git clone https://github.com/zeek/zeek-demo
    $ cd zeek-demo
    $ docker-compose up

## Service Links

After starting running `up`, the following links should be reachable on
the host system. docker-compose is setting up the necessary port forwarding.

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

> **NOTE:** When sending UDP packets at very high rates, you may need
> additional tuning in order to avoid packet drops or packet reordering
> in this setup. See the [Advanced Host Configuration](./doc/advanced.md)
> document in this repository for more details. Note also, this is a demo
> setup and unlikely suitable for production scenarios.

### capture-fwd

A small [gopacket](https://github.com/google/gopacket) based program is located
in the capture-fwd directory. This currently supports VXLAN or GENVE
encapsulation sending the packet a destination IP (default 127.0.0.1).

    $ cd capture-fwd/capture-fwd
    $ go build

    $ sudo ./capture-fwd -i $INTERFACE -encap vxlan -destIp 127.0.0.1 'ip or ip6'

Alternatively, it can read a pcap file and forward its content encapsulated
towards the container (or any other monitoring setup):

    $ sudo ./capture-fwd -delay 0.5ms -r ../pcaps/httpbin-json.pcap -encap vxlan -destIp 127.0.0.1

At this point, you can navigate to the Grafana instance on localhost:13000,
login as zeek/zeek and explore the Zeek Logs dashboard. It should show HTTP
and DNS logs for the `eu.httbin.org` host.

#### Mac OS X with colima

On Mac OSX when using colima as a replacement for Docker Desktop,
[UDP port forwarding is not functional](https://github.com/lima-vm/lima/issues/366).
A [workaround for this limitation exists](https://github.com/rancher-sandbox/rancher-desktop/issues/1611#issuecomment-1176491158).
It involves adding a route to the zeek container network via the VM to
the host side and use the zeek container IP directly as `-destIP` parameter
passed to `capture-fwd`.
