// Based on https://github.com/google/gopacket/blob/master/dumpcommand/tcpdump.go
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")
var destIpStr = flag.String("destIp", "127.0.0.1", "Destination IP")
var destPortInt = flag.Int("destPort", 0, "Destination port")
var vni = flag.Int("vni", 4242, "Virtual Network Identifier")
var encap = flag.String("encap", "vxlan", "vxlan|geneve")
var debug = flag.Bool("debug", false, "Enable debug")

func srcPort(packet gopacket.Packet) int {

	var net_hash uint64 = 0
	var transport_hash uint64 = 0

	if net_layer := packet.NetworkLayer(); net_layer != nil {
		net_flow := net_layer.NetworkFlow()
		net_hash = net_flow.FastHash()
	}
	if transport_layer := packet.TransportLayer(); transport_layer != nil {
		transport_flow := transport_layer.TransportFlow()
		transport_hash = transport_flow.FastHash()
	}

	return int(1024 + (transport_hash+net_hash)%50000)
}

func sendUDP(la, ra *net.UDPAddr, data []byte) error {

	// This may not be safe if someone is already listening
	// on the UDP address. We probably should use raw sockets
	// for sending out the packets instead...
	conn, err := net.DialUDP("udp", la, ra)
	if err != nil {
		return err
	}
	defer conn.Close()

	written, err := conn.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return fmt.Errorf("Not enough bytes written %d != %d", written, len(data))
	}
	return nil
}

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		// This is a little complicated because we want to allow all possible options
		// for creating the packet capture handle... instead of all this you can
		// just call pcap.OpenLive if you want a simple handle.
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatalf("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(*snaplen); err != nil {
			log.Fatalf("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatalf("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatalf("could not set timeout: %v", err)
		}

		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
	}
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}

	// Where are we sending stuff?
	destIp := net.ParseIP(*destIpStr)

	if *destPortInt == 0 {
		if *encap == "vxlan" {
			*destPortInt = 4789
		}
	}

	raddr := net.UDPAddr{IP: destIp, Port: *destPortInt}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// Sniff the packets, encapsulate and then forward.
	for p := range ps.Packets() {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}

		gopacket.SerializeLayers(buf, opts,
			&layers.VXLAN{
				ValidIDFlag: true,
				VNI:         uint32(*vni),
			},
			gopacket.Payload(p.Data()))
		data := buf.Bytes()

		laddr := net.UDPAddr{Port: srcPort(p)}
		if *debug {
			fmt.Printf("Sending %d bytes from %+v to %+v\n", len(data), laddr, raddr)
		}

		if err := sendUDP(&laddr, &raddr, data); err != nil {
			log.Fatal("Failed to send encap packet: ", err)
		}
	}
}
