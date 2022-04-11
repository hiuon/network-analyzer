package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"time"
)

func writeTestFile() string {
	fmt.Println("Do you want to rewrite your test data file? (y/n)")
	var answer string
	_, err := fmt.Scanln(&answer)
	if err != nil {
		return ""
	}
	if answer == "y" {
		var duration int
		for {
			fmt.Println("Enter number of minutes for test (4, 8, 12 .... ): ")
			_, err := fmt.Scanln(&duration)
			if err != nil {
				return ""
			}
			if duration%4 != 0 {
				fmt.Println("Please reenter time...")
			} else {
				break
			}
		}

		f, _ := os.Create("test.pcap")
		w := pcapgo.NewWriter(f)
		err = w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		handle, err = pcap.OpenLive(getDeviceName(), int32(snapshotLen), promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		start := time.Now()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				return ""
			}
			if time.Since(start).Minutes() > float64(duration) {
				break
			}
		}

	}
	return "test.pcap"
}

func getTestDataFromFile() []dataStats {
	handle, err = pcap.OpenOffline("test.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	flagTime := false
	seconds := 0
	var start time.Time
	var stats []dataStats
	stats = append(stats, dataStats{})
	initData(stats, 0)
	for packet := range packetSource.Packets() {
		if !flagTime {
			start = packet.Metadata().Timestamp
			flagTime = true
		}

		if packet.Metadata().Timestamp.Sub(start).Seconds() > float64((seconds+1)*6) {
			seconds++
			stats = append(stats, dataStats{})
			initData(stats, seconds)
		}

		printPacketInfo(packet, stats, seconds)
	}
	return stats
}
