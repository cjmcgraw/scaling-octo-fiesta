package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var ()

func main() {
	handle, err := pcap.OpenLive("enp71s0", 65335, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Printf("inbound packet...\n")
		fmt.Printf("truncated: %t\n", packet.Metadata().Truncated)
		for i, layer := range packet.Layers() {
			fmt.Printf("layer #%d: %s\n", i, layer.LayerType())
		}
		fmt.Println("")
	}
}
