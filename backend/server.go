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
	query := r.URL.Query()
	deviceName := query.Get("deviceName")
	//fmt.Println(deviceName)
	fmt.Fprintln(w, sniffer.StartSnifferFromWeb(deviceName))
}

func stopSniffer(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	fmt.Fprintln(w, sniffer.StopSniffer())
}

func getCurrentParameters(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	query := r.URL.Query()
	typeH := query.Get("type")
	timeInterval := query.Get("interval")
	if timeInterval == "" || typeH == "" {
		w.WriteHeader(444)
		fmt.Fprintln(w, "smth wrong with parameters...")
		return
	}
	timeInt := 0
	if timeInterval == "30" {
		timeInt = 0
	} else if timeInterval == "60" {
		timeInt = 1
	} else if timeInterval == "120" {
		timeInt = 2
	} else if timeInterval == "240" {
		timeInt = 3
	}
	fmt.Fprintln(w, sniffer.GetHurstParamJSON(timeInt, typeH))
}

func StartBackend() {
	http.HandleFunc("/devices", getDevices)
	http.HandleFunc("/start", startSnifferFromWeb)
	http.HandleFunc("/get-data", getCurrentParameters)
	http.HandleFunc("/stop", stopSniffer)

	err := http.ListenAndServe(":5000", nil)
	if err != nil {
		return
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}
