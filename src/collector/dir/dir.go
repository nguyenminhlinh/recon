package dir

import (
	"context"
	"recon/utils"
	"strconv"
	"sync"
)

func DirAndFileBruteForce(ctx context.Context, domain string, wordList string, workDirectory string) {
	utils.Ffuf(domain, "", workDirectory+"/data/output/DirAndFileBruteForce.txt", "dir", false, 2, wordList)
	var wg sync.WaitGroup
	outputChan := make(chan string, 20)
	var count int
	var mu sync.Mutex
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DirAndFileBruteForce.txt", outputChan, &count, &mu, 1)
	var lengths []int
	flagOdd := false //get the item in odd position, start =0
	// domain 0
	// length 1
	// domain 2
	// length 3
	for result := range outputChan {
		if flagOdd {
			length, _ := strconv.Atoi(result)
			lengths = append(lengths, length)
			flagOdd = false
		} else {
			flagOdd = true
		}
	}
	length := FindMostFrequentElement(lengths)
	wg.Wait()
	// Get the length of the first 10 entries to check the most repeated length of the wrong domain then filter by length
	utils.Ffuf(domain, length, workDirectory+"/data/output/DirAndFileBruteForce.txt", "dir", false, 0, wordList)
}

func FindMostFrequentElement(slice []int) string {
	countMap := make(map[int]int)
	var mostFrequent int
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
	return strconv.Itoa(mostFrequent)
}
