package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"math"
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

func getTestHParam(filepath string) {
	var stats []dataStats
	hurstRS := [4]float64{}
	hurstCov := [4]float64{}
	hurstRSDisp := [4]float64{}
	hurstCovDisp := [4]float64{}

	var hurstRS1 []float64
	var hurstRS2 []float64
	var hurstRS3 []float64
	var hurstRS4 []float64

	var hurstCov1 []float64
	var hurstCov2 []float64
	var hurstCov3 []float64
	var hurstCov4 []float64

	handle, err = pcap.OpenOffline(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	flagTime := false
	count := 0
	var start time.Time

	stats = append(stats, dataStats{})
	initData(stats, 0)
	fmt.Println(count)
	for packet := range packetSource.Packets() {
		if !flagTime {
			flagTime = true
			start = packet.Metadata().Timestamp
		}

		if packet.Metadata().Timestamp.Sub(start).Seconds() > float64(5*(count+1)) {
			if (count+1)%6 == 0 {
				hurstRS1 = append(hurstRS1, getHRSReal(stats, count, 6))
				hurstCov1 = append(hurstCov1, getHCov(stats, count, 6))
			}
			if (count+1)%12 == 0 {
				hurstRS2 = append(hurstRS2, getHRSReal(stats, count, 12))
				hurstCov2 = append(hurstCov2, getHCov(stats, count, 12))
			}
			if (count+1)%24 == 0 {
				hurstRS3 = append(hurstRS3, getHRSReal(stats, count, 24))
				hurstCov3 = append(hurstCov3, getHCov(stats, count, 24))
			}
			if (count+1)%48 == 0 {
				hurstRS4 = append(hurstRS4, getHRSReal(stats, count, 48))
				hurstCov4 = append(hurstCov4, getHCov(stats, count, 48))
			}
			count++
			fmt.Println(count)
			stats = append(stats, dataStats{})
			initData(stats, count)
		}
		printPacketInfo(packet, stats, count)
	}
	hurstRS[0] = getMean(hurstRS1)
	hurstRS[1] = getMean(hurstRS2)
	hurstRS[2] = getMean(hurstRS3)
	hurstRS[3] = getMean(hurstRS4)

	hurstCov[0] = getMean(hurstCov1)
	hurstCov[1] = getMean(hurstCov2)
	hurstCov[2] = getMean(hurstCov3)
	hurstCov[3] = getMean(hurstCov4)

	hurstRSDisp[0] = getDisp(hurstRS1, hurstRS[0])
	hurstRSDisp[1] = getDisp(hurstRS2, hurstRS[1])
	hurstRSDisp[2] = getDisp(hurstRS3, hurstRS[2])
	hurstRSDisp[3] = getDisp(hurstRS4, hurstRS[3])

	hurstCovDisp[0] = getDisp(hurstCov1, hurstCov[0])
	hurstCovDisp[1] = getDisp(hurstCov2, hurstCov[1])
	hurstCovDisp[2] = getDisp(hurstCov3, hurstCov[2])
	hurstCovDisp[3] = getDisp(hurstCov4, hurstCov[3])

	fmt.Println(hurstRS)
	fmt.Println(hurstRSDisp)
	fmt.Println(hurstCov)
	fmt.Println(hurstCovDisp)
}

func getMean(data []float64) float64 {
	mean := 0.0
	for i := 0; i < len(data); i++ {
		mean += data[i]
	}
	return mean / float64(len(data))
}

func getDisp(data []float64, mean float64) float64 {
	disp := 0.0
	for i := 0; i < len(data); i++ {
		disp += math.Pow(data[i]-mean, 2)
	}

	disp = math.Sqrt(disp)
	return disp / float64(len(data))
}
