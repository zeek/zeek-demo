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

func srcPort(packet gopacket.Packet) int {

	// TODO: Source port based on flow hash.

	return 51000
}

func sendUDP(la, ra *net.UDPAddr, data []byte) error {
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
		// fmt.Printf("Sending %d bytes from %+v to %+v (%+v)\n", len(data), laddr, raddr, p.TransportLayer())
		// XXX: If we don't do time.sleep() here, there's packet drops
		//      somewhere I'm not yet sure where they are dropped, but
		//      Zeek reports missed_bytes or broken histories if we
		//      don't sleep here.
		//
		//	Maybe we close the socket right away?
		time.Sleep(1 * time.Millisecond)
		if err := sendUDP(&laddr, &raddr, data); err != nil {
			log.Fatal("Failed to send encap packet: ", err)
		}
	}
}
