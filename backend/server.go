package backend

import (
	"Network_Monitor/sniffer"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type key int

const (
	requestIDKey key = 0
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

func getTestData(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	query := r.URL.Query()
	duration := query.Get("duration")
	deviceName := query.Get("deviceName")
	if duration == "" {
		return
	} else {
		intVar, _ := strconv.Atoi(duration)
		if intVar%4 == 0 {
			fmt.Println(w, sniffer.WriteTestFileFromWeb(intVar, deviceName))
		}
	}

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

func getAnomalyCount(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	fmt.Fprintln(w, sniffer.GetAnomalyCount())
}

func logging(targetMux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		targetMux.ServeHTTP(w, r)
		// log request by whom (IP address)
		requesterIP := r.RemoteAddr
		log.Printf(
			"%s\t\t%s\t\t%s\t\t%v",
			r.Method,
			r.RequestURI,
			requesterIP,
			time.Since(start),
		)
	})
}

func StartBackend() {
	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	logger.Println("Server is starting...")

	mux := http.NewServeMux()
	mux.HandleFunc("/devices", getDevices)
	mux.HandleFunc("/start", startSnifferFromWeb)
	mux.HandleFunc("/get-data", getCurrentParameters)
	mux.HandleFunc("/stop", stopSniffer)
	mux.HandleFunc("/get-test-data", getTestData)
	mux.HandleFunc("/get-anomaly-count", getAnomalyCount)

	err := http.ListenAndServe(":5000", logging(mux))
	if err != nil {
		return
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}
