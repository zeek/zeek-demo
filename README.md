# Zeek Demo

This repository contains containers and compose files for plumbing together
the [official Zeek container image](https://hub.docker.com/r/zeek/zeek-dev)
with the [zeek-packet-source-udp](https://github.com/zeek/zeek-packet-source-udp)
plugin and using [systemd](https://github.com/zeek/zeek/tree/master/tools/systemd-generator)
as process supervisor. Further, [Prometheus](https://prometheus.io/), [Loki](https://grafana.com/oss/loki/)
and [Grafana](https://grafana.com/grafana/) are available for demo purposes.

[Zeek logs](https://docs.zeek.org/en/master/logs/index.html) and Zeek metrics
from the [telemetry framework](https://docs.zeek.org/en/master/frameworks/telemetry.html)
can be easily explored in the default Grafana instance's dashboards.

For traffic replay, the idea is to send
[VXLAN](https://www.rfc-editor.org/rfc/rfc7348.html) (or
[GENEVE](https://www.rfc-editor.org/rfc/rfc8926.html))
encapsulated traffic towards 127.0.0.1 on the respective default port of
these tunnel protocols. The compose files configure port forwarding such that
the traffic reaches the Zeek process. In effect, when using VXLAN encapsulation,
Zeek observes the traffic the same way as if it were deployed in an
[AWS traffic monitoring](https://zeek.org/2026/02/using-zeek-with-aws-traffic-mirroring-and-kafka/) environment.

> **NOTE:** Mac OS X with colima does not support UDP forwarding to
> containers, [see below for a workaround](#mac-os-x-with-colima) in
> such setups.

To forward packets captured from local interfaces or replay a pcap, this
repository contains a tool called [capture-fwd](#capture-fwd).
See below for more details.

## Running

Clone the repository and run `docker compose up` within the
[docker-compose-udp](./docker-compose-udp) directory:

    $ git clone https://github.com/zeek/zeek-demo
    $ cd zeek-demo
    $ git submodule update --init --recursive

    $ cd docker-compose-udp
    $ docker compose build && docker compose up

To use [Podman](https://podman.io/) instead of Docker, enter the
[podman-compose-udp](./podman-compose-udp) directory instead:

    $ cd podman-compose-udp
    $ podman compose build && podman compose up

## Service URLs

After running `docker compose up`, the following URLs should be reachable on
your system. Compose is setting up the necessary port forwarding.

    # Grafana (zeek:zeek as credentials)
    http://localhost:13000

    # Loki
    http://localhost:13100

    # Prometheus
    http://localhost:19090

    # VXLAN / Geneve ports forwarded into zeek container.
    127.0.0.1:4789/udp
    127.0.0.1:6081/udp

## Mirroring Traffic

The following instructions describe sending VXLAN encapsulated traffic
towards the container.

> **NOTE:** When sending UDP packets at very high rates, you may need
> additional tuning in order to avoid packet drops or packet reordering.
> See the [Advanced Host Configuration](./doc/advanced.md) document for
> more details. Additionally, this is a demo setup and likely needs some
> tuning to be suitable for production scenarios.

### capture-fwd

A small [gopacket](https://github.com/google/gopacket)-based program is located
in the [capture-fwd](./capture-fwd) directory. This tool supports encapsulation
of packets using the VXLAN or GENVE protocol and sending it to a configurable
destination (default 127.0.0.1).

Example Usage reading packets from a live interface and mirroring them towards
127.0.0.1:4789:

    $ cd capture-fwd/capture-fwd
    $ go build

    $ sudo ./capture-fwd -i $INTERFACE -encap vxlan -destIp 127.0.0.1 'ip or ip6'

Alternatively, ``capture-fwd`` can read a PCAP file and its packets
encapsulated towards the container (or any other monitoring setup):

    $ sudo ./capture-fwd -r ../pcaps/httpbin-json.pcap -encap vxlan -destIp 127.0.0.1

Once you mirrored a few packets, you can navigate to the Grafana instance on localhost:13000,
login suing ``zeek:zeek`` and explore the dashboards. It should show HTTP
and DNS logs for the `eu.httbin.org` host.

#### Mac OS X with colima

On Mac OSX when using colima as a replacement for Docker Desktop,
[UDP port forwarding is not functional](https://github.com/lima-vm/lima/issues/366).
A [workaround for this limitation exists](https://github.com/rancher-sandbox/rancher-desktop/issues/1611#issuecomment-1176491158).
It involves adding a route to the zeek container network via the VM to
the host side and use the zeek container IP directly as `-destIP` parameter
passed to `capture-fwd`.
