package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

func FfufWithMulFunc(domain string, outputfile string, mode string, flagrun bool) {
	Ffuf(domain, "", outputfile, mode, flagrun, 1)
	data := ReadFile(outputfile)
	results := data["results"].([]interface{})
	var lengths []float64
	var maxlength int
	if len(results) > 5 {
		maxlength = 5
	} else {
		maxlength = len(results)
	}

	for _, result := range results[:maxlength] {
		resultMap := result.(map[string]interface{})
		lengths = append(lengths, resultMap["length"].(float64))
	}

	Ffuf(domain, FindMostFrequentElement(lengths), outputfile, mode, false, 0)
}

func FindMostFrequentElement(slice []float64) string {
	countMap := make(map[float64]int)
	var mostFrequent float64
	maxCount := 0
	if len(slice) == 0 {
		return ""
	}
	for _, value := range slice {
		countMap[value]++
		if countMap[value] > maxCount {
			maxCount = countMap[value]
			mostFrequent = value
		}
	}

	return strconv.Itoa(int(mostFrequent))
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
