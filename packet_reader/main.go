package main

import (
	"fmt"
	"log"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	maxPacketSize int = 65535
)

func getBestGuessDeviceName() (string, error) {
	log.Println("scanning available devices that are transmitting...")
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	checkDeviceForValidPackets := func(deviceName string) (string, error) {
		log.Printf("checking device: %s\n", deviceName)
		handle, err := pcap.OpenLive(deviceName, 1, true, 1 * time.Second)
		if err != nil {
			return "", err
		} 
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())

		validPacketCount := 0
		for i:= 0; i < 30; i++ {
			packet, err := packetSrc.NextPacket()
			if err == nil && packet != nil {
				validPacketCount++
			}
		}
		handle.Close()
		if validPacketCount < 20 {
			log.Printf("failed to find active/valid device: %s\n", deviceName)
			return "errors", fmt.Errorf("failed to find valid traffic on device: %s", deviceName)
		}

		log.Printf("found active/valid device: %s\n", deviceName)
		return deviceName, nil
	}

	// Print device information
	log.Println("Devices found:")

	for _, device := range(devices) {
		log.Printf(" - %s\n", device.Name)
	}

	for _, device := range devices {
		if device.Name != "any" {
			result, err := checkDeviceForValidPackets(device.Name)
			if err == nil {
				return result, err
			}
		}
	}
	return "failed", err
}

func main() {
	deviceName, err := getBestGuessDeviceName()
	if err != nil {
		panic(err)
	}

	log.Printf("using device: %s\n", deviceName)
	handle, err := pcap.OpenLive(deviceName, 65535, true, 100 * time.Millisecond)
	if err != nil {
		panic(err)
	}

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSrc.Packets() {
		fmt.Println(packet)
		fmt.Println("")
	}
}
