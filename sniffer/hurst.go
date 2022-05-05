package sniffer

import (
	"fmt"
	"math"
)

func getHRS(stats []dataStats, time int, data *[4]float64, hurstdisp *[4]float64, item int) {

	var ds []int
	// Get max and min values in each interval
	// Вычисляем размах для каждого интервала
	statR := make([]float64, len(ds)/time)
	statS := make([]float64, len(ds)/time)
	statMean := make([]float64, len(ds)/time)
	statH := make([]float64, len(ds)/time)

	for i := 0; i < len(ds)/time; i++ {
		for j := i * time; j < (i+1)*time; j++ {
			statMean[i] += float64(ds[j])
		}
		statMean[i] /= float64(time)
		min := float64(ds[i*time]) - statMean[i]
		max := float64(ds[i*time]) - statMean[i]
		temp := 0.0
		for j := i * time; j < (i+1)*time; j++ {
			temp += float64(ds[j]) - statMean[i]
			if temp > max {
				max = temp
			}
			if temp < min {
				min = temp
			}
		}
		statR[i] = max - min
	}

	for i := 0; i < len(ds)/time; i++ {
		for j := i * time; j < (i+1)*time; j++ {
			statS[i] += math.Pow(float64(ds[j])-statMean[i], 2)
		}
		statS[i] = math.Sqrt(statS[i])
		statS[i] *= math.Sqrt(1.0 / float64(time))

		if statS[i] == 0 || statR[i] == 0 {
			if i == 0 {
				statH[i] = 0.5
			} else {
				statH[i] = statH[i-1]
			}
		} else {
			statH[i] = math.Log10(statR[i]/statS[i]) / math.Log10(float64(time)*0.5)
		}
	}

	mean := 0.0
	disp := 0.0
	for i := 0; i < len(statH); i++ {
		mean += statH[i]
	}
	fmt.Println("time:", time, statH)
	mean /= float64(len(statH))
	for i := 0; i < len(statH); i++ {
		disp += math.Pow(mean-statH[i], 2)
	}
	disp = math.Sqrt(disp * 1.0 / (float64(len(statH)) - 1))

	data[item] = mean
	hurstdisp[item] = disp
}

func getHRSReal(stats []dataStats, index int, length int) float64 {
	ds := make([]int, length)
	for i := 0; i < length; i++ {
		if index-length+1 < 0 {
			return 0.0
		}
		ds[i] = stats[index-length+i+1].protocols["IPv4"]
	}
	// Get max and min values for each interval
	// Вычисляем размах для каждого интервала
	statR := 0.0
	statS := 0.0
	statMean := 0.0

	for i := 0; i < length; i++ {
		statMean += float64(ds[i])
	}
	statMean /= float64(length)
	min := float64(ds[0]) - statMean
	max := float64(ds[0]) - statMean
	temp := 0.0
	for i := 0; i < length; i++ {
		temp += float64(ds[i]) - statMean
		if temp > max {
			max = temp
		}
		if temp < min {
			min = temp
		}
	}
	statR = max - min

	for i := 0; i < length; i++ {
		statS += math.Pow(float64(ds[i])-statMean, 2)
	}
	statS = math.Sqrt(statS)
	statS *= math.Sqrt(1.0 / float64(length))

	statH := 0.0
	if statS == 0 || statR == 0 {
		statH = 0.5
	} else {
		statH = math.Log10(statR/statS) / math.Log10(float64(length)*0.5)
	}
	return statH
}

func getHCov(stats []dataStats, index int, length int) float64 {
	ds := make([]int, length)
	for i := 0; i < length; i++ {
		if index-length+1 < 0 {
			return 0.0
		}
		ds[i] = stats[index-length+i+1].protocols["IPv4"]
	}

	statMean := 0.0

	for i := 0; i < length; i++ {
		statMean += float64(ds[i])
	}
	statMean /= float64(length)

	disp := 0.0
	for i := 0; i < length; i++ {
		disp += math.Pow(float64(ds[i])-statMean, 2)
	}
	disp /= float64(length)

	cov := 0.0
	for i := 0; i < length-1; i++ {
		cov += (float64(ds[i]) - statMean) * (float64(ds[i+1]) - statMean)
	}

	cov /= disp * float64(length-1)
	return 0.5 * (1 + math.Log2(1+cov))
}
