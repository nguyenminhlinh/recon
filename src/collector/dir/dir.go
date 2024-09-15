package dir

import (
	"context"
	"log"
	"recon/utils"
	"strconv"
)

func FuffDirAndFile(ctx context.Context, domain string, wordlist string, WorkDirectory string) {
	utils.Ffuf(domain, "", WorkDirectory+"/data/output/FuffDirAndFile.json", "dir", false, 1, wordlist)
	//Using the wrong tail to get web content
	// lengthResponse := utils.LengthResponse(domain+"/abcdefghiklm", "")
	data := utils.ReadJSONFile(WorkDirectory + "/data/output/FuffDirAndFile.json")

	results, ok := data["results"].([]interface{})
	if !ok {
		log.Fatalf("Error: 'results' is not a valid array")
	}
	var lengths []float64
	var maxlength int
	if len(results) > 10 { //Get only 10 item firstly for check length of fake domain
		maxlength = 10
	} else {
		maxlength = len(results)
	}

	for _, result := range results[:maxlength] {
		resultMap := result.(map[string]interface{})
		lengths = append(lengths, resultMap["length"].(float64))
	}
	utils.Ffuf(domain, FindMostFrequentElement(lengths), WorkDirectory+"/data/output/FuffDirAndFile.json", "dir", false, 0, wordlist)
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
	if maxCount < 5 {
		return ""
	}

	return strconv.Itoa(int(mostFrequent))
}
