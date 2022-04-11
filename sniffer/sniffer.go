package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"time"
)

var (
	promiscuous bool = false
	err         error
	timeout     time.Duration = 2500 * time.Millisecond
	handle      *pcap.Handle
	snapshotLen uint32 = 2048
)

func StartSniffer() {

	device := getDeviceName()
	testFilePath := writeTestFile()
	fmt.Println("Test file is", testFilePath)
	getTestHParam(testFilePath)
	printData(device)
}

func printData(device string) {
	var stats []dataStats
	hurstParam := [4]float64{}
	hurstCov := [4]float64{}
	//hurstDisp := [4]float64{}
	handle, err = pcap.OpenLive(device, int32(snapshotLen), promiscuous, timeout)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	currentTime := time.Now().Unix()
	stats = append(stats, dataStats{})
	initData(stats, 0)
	for {
		//fmt.Println(stats)
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(count, "Error:", err)
			if (count+1)%6 == 0 {
				hurstParam[0] = getHRSReal(stats, count, 6)
				hurstCov[0] = getHCov(stats, count, 6)
			}
			if (count+1)%12 == 0 {
				hurstParam[1] = getHRSReal(stats, count, 12)
				hurstCov[1] = getHCov(stats, count, 12)
			}
			if (count+1)%24 == 0 {
				hurstParam[2] = getHRSReal(stats, count, 24)
				hurstCov[2] = getHCov(stats, count, 24)
			}
			if (count+1)%48 == 0 {
				hurstParam[3] = getHRSReal(stats, count, 48)
				hurstCov[3] = getHCov(stats, count, 48)
			}
			fmt.Println("RS data: ", hurstParam)
			fmt.Println("Cov data: ", hurstCov)
			count += 1
			stats = append(stats, dataStats{})
			initData(stats, count)
			continue
		} else if packet.Metadata().Timestamp.Unix()-currentTime > int64(6*(count+1)) {
			fmt.Println(stats[count].protocols)
			if (count+1)%6 == 0 {
				hurstParam[0] = getHRSReal(stats, count, 6)
				hurstCov[0] = getHCov(stats, count, 6)
			}
			if (count+1)%12 == 0 {
				hurstParam[1] = getHRSReal(stats, count, 12)
				hurstCov[1] = getHCov(stats, count, 12)
			}
			if (count+1)%24 == 0 {
				hurstParam[2] = getHRSReal(stats, count, 24)
				hurstCov[2] = getHCov(stats, count, 24)
			}
			if (count+1)%48 == 0 {
				hurstParam[3] = getHRSReal(stats, count, 48)
				hurstCov[3] = getHCov(stats, count, 48)
			}
			fmt.Println("RS data: ", hurstParam)
			fmt.Println("Cov data: ", hurstCov)
			count += 1
			stats = append(stats, dataStats{})
			initData(stats, count)
		}
		//fmt.Println(packet.Metadata().Timestamp.Unix())
		printPacketInfo(packet, stats, count) // Do something with each packet.
	}
}

func getDeviceName() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for index, device := range devices {
		fmt.Println("\n", index+1, "-> Name: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ")
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}

	fmt.Print("\nEnter number of the device: ")
	var number int
	_, err = fmt.Scanln(&number)
	if err != nil {
		log.Fatal(err)
	}
	return devices[number-1].Name
}

func printPacketInfo(packet gopacket.Packet, data []dataStats, index int) {
	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		ether, _ := etherLayer.(*layers.Ethernet)
		writeStatsProtocol(ether.EthernetType.String(), data, index)
	}
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		writeStatsAddrIp(ip.SrcIP, ip.DstIP, data, index)
		writeStatsProtocol(ip.Protocol.String(), data, index)
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		writeStatsPort(int(tcp.SrcPort), int(tcp.DstPort), data, index)
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		writeStatsPort(int(udp.SrcPort), int(udp.DstPort), data, index)
	}
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
