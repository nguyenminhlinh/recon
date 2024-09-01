package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

func FfufWithMulFunc(domain string, outputfile string, mode string, flagrun bool) {
	Ffuf(domain, "0", outputfile, mode, flagrun, 1)
	data := ReadFile(outputfile)
	results := data["results"].([]interface{})
	var lengths []float64
	for _, result := range results[:5] {
		resultMap := result.(map[string]interface{})
		lengths = append(lengths, resultMap["length"].(float64))
	}
	size := FindMostFrequentElement(lengths)
	Ffuf(domain, strconv.Itoa(int(size)), outputfile, mode, false, 0)
}

func FindMostFrequentElement(slice []float64) float64 {
	countMap := make(map[float64]int)
	var mostFrequent float64
	maxCount := 0

	for _, value := range slice {
		countMap[value]++
		if countMap[value] > maxCount {
			maxCount = countMap[value]
			mostFrequent = value
		}
	}

	return mostFrequent
}

func printOption(name []byte, value []byte) {
	fmt.Fprintf(os.Stderr, " :: %-16s : %s\n", name, value)
}
func LengthResponse(domain string) int {
	req, err := http.NewRequest("GET", "http://"+domain, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		os.Exit(1)
	}
	req.Header.Set("Host", "abcdefghiklmnopq."+domain)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		os.Exit(1)
	}
	return len(body)
}
