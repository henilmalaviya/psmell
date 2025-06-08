package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/henilmalaviya/psmell/pkg/psmell"
)

func main() {
	iface := flag.String("i", "eth0", "Interface to sniff")
	jsonOut := flag.Bool("json", false, "Output in JSON format")

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	cchan := make(chan os.Signal, 1)
	signal.Notify(cchan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-cchan
		cancel()
	}()

	sniffer, err := psmell.NewSniffer(*iface, 65535)

	if err != nil {
		panic(err)
	}

	packets, err := sniffer.Sniff(ctx)

	if err != nil {
		panic(err)
	}

	for pkt := range packets {

		if *jsonOut {
			b, _ := json.Marshal(pkt)
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s | %s:%d -> %s:%d | %s | %d\n", pkt.Timestamp, pkt.SrcIp, pkt.SrcPort, pkt.DstIp, pkt.DstPort, pkt.Protocol, pkt.Length)
		}

	}

}
