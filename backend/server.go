package backend

import (
	"Network_Monitor/sniffer"
	"fmt"
	"net/http"
)

func getDevices(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	fmt.Fprintln(w, sniffer.GetDevicesJSON())
}

func startSnifferFromWeb(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	fmt.Fprintln(w, sniffer.GetDevicesJSON())
}

func StartBackend() {
	http.HandleFunc("/devices", getDevices)
	http.HandleFunc("/start", startSnifferFromWeb)

	err := http.ListenAndServe(":5000", nil)
	if err != nil {
		return
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}
