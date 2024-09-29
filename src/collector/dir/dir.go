package dir

import (
	"context"
	"recon/utils"
	"recon/utils/output"
	"strconv"
)

func DirAndFileBruteForce(ctx context.Context, domain string, wordList string) map[string]int64 {
	var outputMap map[string]int64
	utils.Ffuf(domain, "", "DirAndFileBruteForce", "dir", false, 1, wordList)
	outputMap = output.OutputDirAndFile
	var lengths []int64

	for _, value := range outputMap {
		lengths = append(lengths, value)
	}

	length := FindMostFrequentElement(lengths) //get length most frequent to remove result have this length for the sencond run
	// Get the length of the first 10 entries to check the most repeated length of the wrong domain then filter by length
	utils.Ffuf(domain, length, "DirAndFileBruteForce", "dir", false, 0, wordList)
	return output.OutputDirAndFile
}

func FindMostFrequentElement(slice []int64) string {
	countMap := make(map[int64]int)
	var mostFrequent int64
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
	return strconv.FormatInt(mostFrequent, 10)
}
