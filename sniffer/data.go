package sniffer

import (
	"encoding/binary"
	"net"
)

type hParam struct {
	h          float64
	highBorder float64
	lowBorder  float64
	timestamp  string
}

type deviceStruct struct {
	Name string
	IPv4 string
	Mask string
}

type dataStats struct {
	srcPort   map[int]int
	dstPort   map[int]int
	protocols map[string]int
	srcAddrIp map[int]int
	dstAddrIp map[int]int
}

func initData(ds []dataStats, index int) {
	ds[index].srcPort = make(map[int]int)
	ds[index].dstPort = make(map[int]int)
	ds[index].protocols = make(map[string]int)
	ds[index].srcAddrIp = make(map[int]int)
	ds[index].dstAddrIp = make(map[int]int)
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func writeStatsPort(src int, dst int, data []dataStats, index int) {
	data[index].srcPort[src] += 1
	data[index].dstPort[dst] += 1
}

func writeStatsAddrIp(src net.IP, dst net.IP, data []dataStats, index int) {
	srcAddr := ip2int(src)
	dstAddr := ip2int(dst)
	data[index].srcAddrIp[int(srcAddr)] += 1
	data[index].dstAddrIp[int(dstAddr)] += 1
}

func writeStatsProtocol(protocol string, data []dataStats, index int) {
	data[index].protocols[protocol] += 1
}
