package psmell

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIp     net.IP    `json:"src_ip"`
	DstIp     net.IP    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Length    int       `json:"length"`
	RawData   []byte    `json:"-"`
}

func parsePacket(pkt gopacket.Packet) *Packet {

	networkLayer := pkt.NetworkLayer()
	transportLayer := pkt.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return nil
	}

	var srcIp, dstIp net.IP

	switch ipLayer := networkLayer.(type) {
	case *layers.IPv4:
		srcIp = ipLayer.SrcIP
		dstIp = ipLayer.DstIP
	case *layers.IPv6:
		srcIp = ipLayer.SrcIP
		dstIp = ipLayer.DstIP
	}

	var srcPort, dstPort uint16
	var prot string

	switch tcpLayer := transportLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(tcpLayer.SrcPort)
		dstPort = uint16(tcpLayer.DstPort)
		prot = "TCP"
	case *layers.UDP:
		srcPort = uint16(tcpLayer.SrcPort)
		dstPort = uint16(tcpLayer.DstPort)
		prot = "UDP"
	default:
		return nil
	}

	pktData := pkt.Data()

	return &Packet{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIp:     srcIp,
		DstIp:     dstIp,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  prot,
		Length:    len(pktData),
		RawData:   pktData,
	}
}
