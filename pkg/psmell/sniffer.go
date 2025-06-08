package psmell

import (
	"context"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type SnifferInterface interface {
	Sniff(context context.Context) (<-chan *Packet, error)
}

type Sniffer struct {
	iface   string
	snaplen int

	handle *pcap.Handle
}

func NewSniffer(iface string, snaplen int) (*Sniffer, error) {

	handle, err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)

	if err != nil {
		return nil, err
	}

	return &Sniffer{
		iface:   iface,
		snaplen: snaplen,

		handle: handle,
	}, nil
}

func (s *Sniffer) Sniff(context context.Context) (<-chan *Packet, error) {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	channel := make(chan *Packet)

	go func() {

		defer close(channel)

		for {
			select {
			case <-context.Done():
				return
			case pkt, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				parsed := parsePacket(pkt)
				if parsed != nil {
					channel <- parsed
				}
			}

		}

	}()

	return channel, nil
}
