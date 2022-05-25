package sniffer

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"time"
)

var (
	promiscuous     bool = false
	err             error
	timeout         time.Duration = 2500 * time.Millisecond
	handle          *pcap.Handle
	snapshotLen     uint32 = 2048
	hurstRS                = [4]float64{}
	hurstCov               = [4]float64{}
	hurstRSDisp            = [4]float64{}
	hurstCovDisp           = [4]float64{}
	hurstRSRealAll  [4][]hParam
	hurstCovRealAll [4][]hParam
	anomalyRScount  = [4]int{}
	anomalyCovcount = [4]int{}
	globalCountRS   = 0
	globalCountCov  = 0
	quit            = make(chan bool)
)

func StartSniffer() {

	device := getDeviceName()
	testFilePath := writeTestFile()
	fmt.Println("Test file is", testFilePath)
	getTestHParam(testFilePath)
	printData(device)
}

func writeDataToGlobal(index int, stats []dataStats, realCov *[4]float64, realRS *[4]float64, count int, length int) {
	realRS[index] = getHRSReal(stats, count, length)
	realCov[index] = getHCov(stats, count, length)
	hurstRSRealAll[index] = append(hurstRSRealAll[index], hParam{
		H:          realRS[index],
		HighBorder: hurstRS[index] + 3*hurstRSDisp[index],
		LowBorder:  hurstRS[index] - 3*hurstRSDisp[index],
		Timestamp:  time.Now().String(),
	})
	hurstCovRealAll[index] = append(hurstCovRealAll[index], hParam{
		H:          realCov[index],
		HighBorder: hurstCov[index] + 3*hurstCovDisp[index],
		LowBorder:  hurstCov[index] - 3*hurstCovDisp[index],
		Timestamp:  time.Now().String(),
	})
	checkParameters(realRS, realCov, index, length)
}

func printData(device string) {
	var stats []dataStats
	hurstRSReal := [4]float64{}
	hurstCovReal := [4]float64{}
	//hurstDisp := [4]float64{}
	handle, err = pcap.OpenLive(device, int32(snapshotLen), promiscuous, timeout)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	currentTime := time.Now().Unix()
	stats = append(stats, dataStats{})
	initData(stats, 0)
	for {
		select {
		case <-quit:
			return
		default:
			//fmt.Println(stats)
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Println(count, "Error:", err)
				if (count+1)%6 == 0 {
					writeDataToGlobal(0, stats, &hurstCovReal, &hurstRSReal, count, 6)
				}
				if (count+1)%12 == 0 {
					writeDataToGlobal(1, stats, &hurstCovReal, &hurstRSReal, count, 12)
				}
				if (count+1)%24 == 0 {
					writeDataToGlobal(2, stats, &hurstCovReal, &hurstRSReal, count, 24)
				}
				if (count+1)%48 == 0 {
					writeDataToGlobal(3, stats, &hurstCovReal, &hurstRSReal, count, 48)
				}
				fmt.Println("RS data: ", hurstRSReal)
				fmt.Println("Cov data: ", hurstCovReal)
				count += 1
				stats = append(stats, dataStats{})
				initData(stats, count)
				continue
			} else if packet.Metadata().Timestamp.Unix()-currentTime > int64(6*(count+1)) {
				//fmt.Println(stats[count].protocols)
				if (count+1)%6 == 0 {
					writeDataToGlobal(0, stats, &hurstCovReal, &hurstRSReal, count, 6)
				}
				if (count+1)%12 == 0 {
					writeDataToGlobal(1, stats, &hurstCovReal, &hurstRSReal, count, 12)
				}
				if (count+1)%24 == 0 {
					writeDataToGlobal(2, stats, &hurstCovReal, &hurstRSReal, count, 24)
				}
				if (count+1)%48 == 0 {
					writeDataToGlobal(3, stats, &hurstCovReal, &hurstRSReal, count, 48)
				}
				fmt.Println("RS data: ", hurstRSReal)
				fmt.Println("Cov data: ", hurstCovReal)
				count += 1
				stats = append(stats, dataStats{})
				initData(stats, count)
			}
			//fmt.Println(packet.Metadata().Timestamp.Unix())
			//fmt.Println(hurstCovRealAll)
			printPacketInfo(packet, stats, count) // Do something with each packet.
		}
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

func GetDevicesJSON() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var temp []deviceStruct
	for index, device := range devices {
		temp = append(temp, deviceStruct{})
		temp[index].Name = device.Description
		//fmt.Println("- Subnet mask: ", device.Name)
		for _, address := range device.Addresses {
			temp[index].IPv4 = address.IP.String()
			temp[index].Mask = address.Netmask.String()
		}
	}
	//fmt.Println(time.Now())
	jsonData, err := json.Marshal(temp)
	if err != nil {
		log.Fatal(err)
	}
	return string(jsonData)
}

func GetHurstParamJSON(index int, cal string) string {
	var temp []hParam
	for i := 0; i < 20; i++ {
		if cal == "1" {
			if i+len(hurstCovRealAll[index]) < 20 {
				continue
			}
			temp = append(temp, hurstCovRealAll[index][len(hurstCovRealAll[index])-20+i])
		} else {
			if i+len(hurstRSRealAll[index]) < 20 {
				continue
			}
			temp = append(temp, hurstRSRealAll[index][len(hurstRSRealAll[index])-20+i])
		}

	}
	//fmt.Println(temp)
	jsonData, err := json.Marshal(temp)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println("1:", string(jsonData))
	return string(jsonData)
}

func StartSnifferFromWeb(deviceName string) string {
	//quit <- false
	getTestHParam("test.pcap")
	go printData(getDeviceNameFromIP(deviceName))
	return "{}"
}

func getDeviceNameFromIP(IP string) string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.String() == IP {
				return device.Name
			}
		}
	}
	return ""
}

func StopSniffer() string {
	quit <- true
	return "{}"
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

func checkParameters(hRS *[4]float64, hCov *[4]float64, index int, length int) {
	if (hRS[index] > hurstRS[index]+3*hurstRSDisp[index] || hRS[index] < hurstRS[index]-3*hurstRSDisp[index]) && (hRS[index] > 0 && hRS[index] < 1) {
		anomalyRScount[index] += 1
		fmt.Println(index, "smth wrong with network (RS)")
	}

	if (hCov[index] > hurstCov[index]+3*hurstCovDisp[index] || hCov[index] < hurstCov[index]-3*hurstCovDisp[index]) && (hRS[index] > 0 && hRS[index] < 1) {
		anomalyCovcount[index] += 1
		fmt.Println(index, "smth wrong with network (Cov)")
	}

	fmt.Println(anomalyRScount, globalCountRS)
	if length == 48 {
		temp1 := 0
		temp2 := 0
		for i := 0; i < len(anomalyRScount); i++ {
			temp1 += anomalyRScount[i]
			temp2 += anomalyCovcount[i]
		}
		globalCountRS = temp1 - globalCountRS
		globalCountCov = temp2 - globalCountCov
	}
}

func GetAnomalyCount() string {
	var temp []int
	for i := 0; i < len(anomalyRScount); i++ {
		temp = append(temp, anomalyRScount[i])
	}
	temp = append(temp, globalCountRS)
	for i := 0; i < len(anomalyCovcount); i++ {
		temp = append(temp, anomalyCovcount[i])
	}
	temp = append(temp, globalCountCov)

	jsonData, err := json.Marshal(temp)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println("1:", string(jsonData))
	return string(jsonData)
}
