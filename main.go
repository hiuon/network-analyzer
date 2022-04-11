package main

import (
	sniffer "Network_Monitor/sniffer"
	"fmt"
)

func main() {
	sniffer.StartSniffer()
	fmt.Println("Hello world!")
}
