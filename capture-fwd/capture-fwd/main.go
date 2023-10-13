// Capture-replay-forward utility
//
// Encapsulates network packets sniffed from a local network interface (-i)
// or read from a pcap (-r) with VXLAN or GENEVE. Then either forward them
// via UDP to destIp:destPort or write the packets encapsulated into a
// pcap file (-w).
//
// For sending UDP packets and sniffing from interfaces, NET_CAP_RAW
// is required on Linux.
//
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
	"github.com/google/gopacket/pcapgo"
)

var iface = flag.String("i", "", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var wfname = flag.String("w", "", "Filename to write pcap to, overrides -destIp and -destPort")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")
var destIpStr = flag.String("destIp", "127.0.0.1", "Destination IP")
var srcIpStr = flag.String("srcIp", "127.0.0.1", "Source IP when writing to pcap file")
var srcMacStr = flag.String("srcMac", "0C:55:21:83:13:6D", "Source MAC address when writing to pcap file")
var destMacStr = flag.String("destMac", "0C:55:21:83:13:6E", "Destination MAC when writing to pcap file")
var destPortInt = flag.Int("destPort", 0, "Destination port. 4789 for VXLAN, 6081 for GENEVE")
var vni = flag.Int("vni", 4242, "Virtual Network Identifier")
var encap = flag.String("encap", "vxlan", "vxlan|geneve")
var debug = flag.Bool("debug", false, "Enable debug")
var pktDelay = flag.Duration("delay", 0, "Delay after sending a packet.")
var pktRate = flag.Float64("p", 0, "Replay with a fixed rate.")
var dltRaw = flag.Bool("dltRaw", false, "Create a DLT_RAW pcap without ethernet layer")

// Inner flow-hashing to determine UDP source port.
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

type PacketDelayer struct {
	delay            time.Duration
	last_packet_time time.Time
	last_write_time  time.Time
}

func (pd *PacketDelayer) Delay(p gopacket.Packet) {

	if !pd.last_packet_time.IsZero() {

		now := time.Now()
		elapsed := now.Sub(pd.last_write_time)

		delay := pd.delay
		// Take the packet time
		if delay == 0 {
			delay = p.Metadata().Timestamp.Sub(pd.last_packet_time)
			if delay < 0 {
				log.Printf("ERROR Negative delay? %v", delay)
				delay = 0
			}
		}

		to_sleep := delay - elapsed
		if *debug {
			fmt.Printf("Delaying for %v\n", to_sleep)
		}
		if to_sleep > 0 {
			time.Sleep(to_sleep)
		}
	}
	pd.last_packet_time = p.Metadata().Timestamp
	pd.last_write_time = time.Now()
}

type PacketOutputter interface {
	// Output buf to a destination using opts. The original packet can be found in p
	Output(p gopacket.Packet, opts gopacket.SerializeOptions, buf gopacket.SerializeBuffer) error
}

type UdpOutputter struct {
	conn    *net.IPConn
	delayer PacketDelayer
}

func (o *UdpOutputter) Output(p gopacket.Packet, opts gopacket.SerializeOptions, buf gopacket.SerializeBuffer) error {

	o.delayer.Delay(p)

	data := buf.Bytes()
	written, err := o.conn.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return fmt.Errorf("Not enough bytes written %d != %d", written, len(data))
	}
	return nil
}

type PcapOutputter struct {
	outer_layers []gopacket.SerializableLayer
	writer       *pcapgo.Writer
}

func (o *PcapOutputter) Output(p gopacket.Packet, opts gopacket.SerializeOptions, buf gopacket.SerializeBuffer) (err error) {

	// Prepend the provided outer layers
	for i := len(o.outer_layers) - 1; i >= 0; i-- {
		if err = o.outer_layers[i].SerializeTo(buf, opts); err != nil {
			return err
		}
	}

	data := buf.Bytes()
	info := gopacket.CaptureInfo{
		Timestamp:     p.Metadata().Timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}
	return o.writer.WritePacket(info, data)
}

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else if *iface != "" {
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
	} else {
		log.Fatal("Neither -i nor -r used")
	}

	if *pktDelay > 0 && *pktRate > 0 {
		log.Fatal("Provide either -delay or -p, not both")
	} else if *pktRate > 0 {
		*pktDelay = time.Duration(1.0 / *pktRate * 1000000000)
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

		// If the pcap is DLT_RAW, use IPv4 ethernet type.
		//
		// TODO: This really depends what is actually in the
		//       pcap, it could have IPv6 and IPv4 mixed.
		protocol := layers.EthernetTypeTransparentEthernetBridging
		if handle.LinkType() == layers.LinkTypeRaw || handle.LinkType() == 12 {
			protocol = layers.EthernetTypeIPv4
		}

		encap_layer = &layers.Geneve{
			Version:  0,
			VNI:      uint32(*vni),
			Protocol: protocol,
		}
	} else {
		log.Fatal("Unknown encap: ", *encap)
	}

	var outputter PacketOutputter
	var ip_layer layers.IPv4 // Fixme IPv6 support?
	destIp := net.ParseIP(*destIpStr)

	if *wfname != "" {
		link_type := layers.LinkTypeEthernet
		var outer_layers []gopacket.SerializableLayer

		if !*dltRaw {
			srcMac, err := net.ParseMAC(*srcMacStr)
			if err != nil {
				log.Fatal("Bad srcMac", err)
			}
			destMac, err := net.ParseMAC(*destMacStr)
			if err != nil {
				log.Fatal("Bad destMac", err)
			}

			eth_type := layers.EthernetTypeIPv4
			eth_layer := layers.Ethernet{
				SrcMAC:       srcMac,
				DstMAC:       destMac,
				EthernetType: eth_type,
			}
			outer_layers = append(outer_layers, &eth_layer)
		} else {
			link_type = layers.LinkTypeRaw
		}

		// When writing to a pcap, need to provide an explicit srcIp
		ip_layer = layers.IPv4{
			Version:  4,
			SrcIP:    net.ParseIP(*srcIpStr),
			DstIP:    destIp,
			TTL:      32,
			Protocol: layers.IPProtocolUDP,
		}

		outer_layers = append(outer_layers, &ip_layer)

		f, err := os.Create(*wfname)
		if err != nil {
			log.Fatal("Failed to open pcap for writing:", err)
		}
		defer f.Close()

		w := pcapgo.NewWriter(f)
		w.WriteFileHeader(65536, link_type)

		outputter = &PcapOutputter{
			outer_layers: outer_layers,
			writer:       w,
		}

	} else {
		raddr := net.IPAddr{IP: destIp}
		conn, err := net.DialIP("ip:udp", nil, &raddr)
		if err != nil {
			log.Fatal("DialIP error:", err)
		}
		defer conn.Close()

		if *debug {
			fmt.Printf("Source address for UDP packets: %v\n", conn.LocalAddr())
		}

		ip_layer = layers.IPv4{
			SrcIP: net.ParseIP(conn.LocalAddr().String()),
			DstIP: net.ParseIP(conn.RemoteAddr().String()),
		}

		outputter = &UdpOutputter{
			conn: conn,
			delayer: PacketDelayer{
				delay: *pktDelay,
			},
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range ps.Packets() {

		transport_layer := layers.UDP{
			SrcPort: layers.UDPPort(srcPort(p)),
			DstPort: layers.UDPPort(*destPortInt),
		}
		transport_layer.SetNetworkLayerForChecksum(&ip_layer)

		payload := gopacket.Payload(p.Data())

		gopacket.SerializeLayers(buf, opts,
			&transport_layer,
			encap_layer,
			payload,
		)

		if *debug {
			fmt.Printf("Outputting %d bytes from %v:%d to %v:%v\n", len(buf.Bytes()), ip_layer.SrcIP, transport_layer.SrcPort, destIp, *destPortInt)
		}

		if err := outputter.Output(p, opts, buf); err != nil {
			log.Fatal("Failed to output packet: ", err)
		}
	}
}
