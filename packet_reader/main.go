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
		fmt.Println(packet.Dump())

		if errorLayer := packet.ErrorLayer(); errorLayer != nil {
			fmt.Printf("  errors decoding layer: %s\n", errorLayer)
		}
		fmt.Println("  Link Layer:")
		if linkLayer := packet.LinkLayer(); linkLayer != nil {
			flow := linkLayer.LinkFlow()
			fmt.Printf("    type: %s\n", linkLayer.LayerType())
			fmt.Printf("    format: %s\n", flow.EndpointType())
			fmt.Printf("    source MAC addr: %s\n", flow.Src())
			fmt.Printf("    dest MAC addr: %s\n", flow.Dst())
		} else {
			fmt.Printf("  Unknown link packet!")
		}

		fmt.Println("  Network Layer:")
		if networkLayer := packet.NetworkLayer(); networkLayer != nil {
			flow := networkLayer.NetworkFlow()
			fmt.Printf("    type: %s\n", networkLayer.LayerType())
			fmt.Printf("    format: %s\n", flow.EndpointType())
			fmt.Printf("    source ip: %s\n", flow.Src())
			fmt.Printf("    dest ip: %s\n", flow.Dst())
		} else {
			fmt.Println("  Unknown network packet!")
		}

		fmt.Println("")
	}
}
