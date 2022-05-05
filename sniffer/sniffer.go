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
	fmt.Println(GetDevicesJSON())
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
		//fmt.Println(stats)
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(count, "Error:", err)
			if (count+1)%6 == 0 {
				hurstRSReal[0] = getHRSReal(stats, count, 6)
				hurstCovReal[0] = getHCov(stats, count, 6)
				hurstRSRealAll[0] = append(hurstRSRealAll[0], hParam{
					H:          hurstRSReal[0],
					HighBorder: hurstRS[0] + 3*hurstRSDisp[0],
					LowBorder:  hurstRS[0] - 3*hurstRSDisp[0],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[0] = append(hurstCovRealAll[0], hParam{
					H:          hurstCovReal[0],
					HighBorder: hurstCov[0] + 3*hurstCovDisp[0],
					LowBorder:  hurstCov[0] - 3*hurstCovDisp[0],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 0)
			}
			if (count+1)%12 == 0 {
				hurstRSReal[1] = getHRSReal(stats, count, 12)
				hurstCovReal[1] = getHCov(stats, count, 12)
				hurstRSRealAll[1] = append(hurstRSRealAll[1], hParam{
					H:          hurstRSReal[1],
					HighBorder: hurstRS[1] + 3*hurstRSDisp[1],
					LowBorder:  hurstRS[1] - 3*hurstRSDisp[1],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[0] = append(hurstCovRealAll[1], hParam{
					H:          hurstCovReal[1],
					HighBorder: hurstCov[1] + 3*hurstCovDisp[1],
					LowBorder:  hurstCov[1] - 3*hurstCovDisp[1],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 1)
			}
			if (count+1)%24 == 0 {
				hurstRSReal[2] = getHRSReal(stats, count, 24)
				hurstCovReal[2] = getHCov(stats, count, 24)
				hurstRSRealAll[2] = append(hurstRSRealAll[2], hParam{
					H:          hurstRSReal[2],
					HighBorder: hurstRS[2] + 3*hurstRSDisp[2],
					LowBorder:  hurstRS[2] - 3*hurstRSDisp[2],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[2] = append(hurstCovRealAll[2], hParam{
					H:          hurstCovReal[2],
					HighBorder: hurstCov[2] + 3*hurstCovDisp[2],
					LowBorder:  hurstCov[2] - 3*hurstCovDisp[2],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 2)
			}
			if (count+1)%48 == 0 {
				hurstRSReal[3] = getHRSReal(stats, count, 48)
				hurstCovReal[3] = getHCov(stats, count, 48)
				hurstRSRealAll[3] = append(hurstRSRealAll[3], hParam{
					H:          hurstRSReal[0],
					HighBorder: hurstRS[3] + 3*hurstRSDisp[3],
					LowBorder:  hurstRS[3] - 3*hurstRSDisp[3],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[3] = append(hurstCovRealAll[3], hParam{
					H:          hurstCovReal[3],
					HighBorder: hurstCov[3] + 3*hurstCovDisp[3],
					LowBorder:  hurstCov[3] - 3*hurstCovDisp[3],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 3)
			}
			fmt.Println("RS data: ", hurstRSReal)
			fmt.Println("Cov data: ", hurstCovReal)
			count += 1
			stats = append(stats, dataStats{})
			initData(stats, count)
			continue
		} else if packet.Metadata().Timestamp.Unix()-currentTime > int64(6*(count+1)) {
			fmt.Println(stats[count].protocols)
			if (count+1)%6 == 0 {
				hurstRSReal[0] = getHRSReal(stats, count, 6)
				hurstCovReal[0] = getHCov(stats, count, 6)
				hurstRSRealAll[0] = append(hurstRSRealAll[0], hParam{
					H:          hurstRSReal[0],
					HighBorder: hurstRS[0] + 3*hurstRSDisp[0],
					LowBorder:  hurstRS[0] - 3*hurstRSDisp[0],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[0] = append(hurstCovRealAll[0], hParam{
					H:          hurstCovReal[0],
					HighBorder: hurstCov[0] + 3*hurstCovDisp[0],
					LowBorder:  hurstCov[0] - 3*hurstCovDisp[0],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 0)
			}
			if (count+1)%12 == 0 {
				hurstRSReal[1] = getHRSReal(stats, count, 12)
				hurstCovReal[1] = getHCov(stats, count, 12)
				hurstRSRealAll[1] = append(hurstRSRealAll[1], hParam{
					H:          hurstRSReal[1],
					HighBorder: hurstRS[1] + 3*hurstRSDisp[1],
					LowBorder:  hurstRS[1] - 3*hurstRSDisp[1],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[1] = append(hurstCovRealAll[1], hParam{
					H:          hurstCovReal[1],
					HighBorder: hurstCov[1] + 3*hurstCovDisp[1],
					LowBorder:  hurstCov[1] - 3*hurstCovDisp[1],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 1)
			}
			if (count+1)%24 == 0 {
				hurstRSReal[2] = getHRSReal(stats, count, 24)
				hurstCovReal[2] = getHCov(stats, count, 24)
				hurstRSRealAll[2] = append(hurstRSRealAll[2], hParam{
					H:          hurstRSReal[2],
					HighBorder: hurstRS[2] + 3*hurstRSDisp[2],
					LowBorder:  hurstRS[2] - 3*hurstRSDisp[2],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[2] = append(hurstCovRealAll[2], hParam{
					H:          hurstCovReal[2],
					HighBorder: hurstCov[2] + 3*hurstCovDisp[2],
					LowBorder:  hurstCov[2] - 3*hurstCovDisp[2],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 2)
			}
			if (count+1)%48 == 0 {
				hurstRSReal[3] = getHRSReal(stats, count, 48)
				hurstCovReal[3] = getHCov(stats, count, 48)
				hurstRSRealAll[3] = append(hurstRSRealAll[3], hParam{
					H:          hurstRSReal[3],
					HighBorder: hurstRS[3] + 3*hurstRSDisp[3],
					LowBorder:  hurstRS[3] - 3*hurstRSDisp[3],
					Timestamp:  time.Now().String(),
				})
				hurstCovRealAll[3] = append(hurstCovRealAll[3], hParam{
					H:          hurstCovReal[3],
					HighBorder: hurstCov[3] + 3*hurstCovDisp[3],
					LowBorder:  hurstCov[3] - 3*hurstCovDisp[3],
					Timestamp:  time.Now().String(),
				})
				checkParameters(hurstRSReal, hurstCovReal, 3)
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
		fmt.Println("- Subnet mask: ", device.Name)
		for _, address := range device.Addresses {
			temp[index].IPv4 = address.IP.String()
			temp[index].Mask = address.Netmask.String()
		}
	}
	fmt.Println(time.Now())
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

func StartSnifferFromWeb() string {
	go loop()
	return "{}"
}

func loop() {
	i := 0
	for {
		time.Sleep(2 * time.Second)
		i++
		fmt.Println(i)
	}
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

func checkParameters(hRS [4]float64, hCov [4]float64, index int) {
	if hRS[index] > hurstRS[index]+3*hurstRSDisp[index] || hRS[index] < hurstRS[index]-3*hurstRSDisp[index] {
		fmt.Println(index, "smth wrong with network (RS)")
	}

	if hCov[index] > hurstCov[index]+3*hurstCovDisp[index] || hCov[index] < hurstCov[index]-3*hurstCovDisp[index] {
		fmt.Println(index, "smth wrong with network (Cov)")
	}
}
