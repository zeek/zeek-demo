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

func srcPort(packet gopacket.Packet) uint16 {

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

	return uint16(1024 + (transport_hash+net_hash)%50000)
}

func sendData(conn *net.IPConn, data []byte) error {

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

	var encap_layer gopacket.SerializableLayer
	if *encap == "vxlan" {
		if *destPortInt == 0 {
			*destPortInt = 4789
		}
		encap_layer = &layers.VXLAN{
			ValidIDFlag: true,
			VNI:         uint32(*vni),
		}
	} else if *encap == "geneve" {
		if *destPortInt == 0 {
			*destPortInt = 6081
		}
		encap_layer = &layers.Geneve{
			Version: 0,
			VNI:     uint32(*vni),
			// XXX: Is this always right?
			Protocol: layers.EthernetTypeTransparentEthernetBridging,
		}

	} else {
		log.Fatal("Unknown encap: ", *encap)
	}

	// Where are we sending stuff?
	destIp := net.ParseIP(*destIpStr)
	raddr := net.IPAddr{IP: destIp}
	conn, err := net.DialIP("ip:udp", nil, &raddr)
	if err != nil {
		log.Fatal("DialIP error:", err)
	}
	defer conn.Close()

	if *debug {
		fmt.Printf("local=%v\n", conn.LocalAddr())
	}

	// Pseudo header required for checksum computation. This
	// isn't serialized
	pseudo_ip_layer := layers.IPv4{
		SrcIP: net.ParseIP(conn.LocalAddr().String()),
		DstIP: net.ParseIP(conn.RemoteAddr().String()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range ps.Packets() {

		transport_layer := layers.UDP{
			SrcPort:  layers.UDPPort(srcPort(p)),
			DstPort:  layers.UDPPort(*destPortInt),
			Checksum: 0, // 0 means ignored. We could do better if know the addresses
		}
		transport_layer.SetNetworkLayerForChecksum(&pseudo_ip_layer)

		payload := gopacket.Payload(p.Data())

		gopacket.SerializeLayers(buf, opts,
			&transport_layer,
			encap_layer,
			payload,
		)

		if *debug {
			fmt.Printf("Sending %d bytes from %v:%d to %v:%v\n", len(buf.Bytes()), pseudo_ip_layer.SrcIP, transport_layer.SrcPort, destIp, *destPortInt)
		}

		if err := sendData(conn, buf.Bytes()); err != nil {
			log.Fatal("Failed to send encap packet: ", err)
		}
	}
}
