package main

import (
	"context"
	"fmt"
	"os"
	"recon/core"
	"recon/utils"
	"sync"
	"time"
)

const (
	BANNER_HEADER = `
 █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║██║   ██║   ██║   ██║   ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝`
	BANNER_SEP = "__________________________________________________________________________________"
)

func main() {
	start := time.Now()
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//utils.CancelRun(cancel)
	utils.StopRun()
	workDirectory := utils.Getwd()
	count := 0
	var mu sync.Mutex
	const maxChanResults = 100 // Limit the number of elements in chan results
	const maxChanResult = 50   // Limit the number of elements in chan results
	const maxGoroutines = 4
	chanResults := make(chan string, maxChanResults)
	chanResultsDNS := make(chan string, maxChanResult)
	chanResultsHttp := make(chan string, maxChanResult)
	chanResultsAmass := make(chan string, maxChanResult)
	chanResultsSubfinder := make(chan string, maxChanResult)
	chanResultsDirAndFile := make(chan string, maxChanResult)

	// Get command from console
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <domain>")
		os.Exit(1)
	}
	domainName := os.Args[1]

	fmt.Fprintf(os.Stderr, "%s\n       %+60s\n%s\n", BANNER_HEADER, "Made by MinhLinh", BANNER_SEP)
	fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", "Scanning target", domainName)

	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainBruteForceHttp", chanResultsHttp)
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainBruteForceDNS", chanResultsDNS)
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainOSINTAmass", chanResultsAmass)
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainOSINTSubfinder", chanResultsSubfinder)
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DirAndFileBruteForce", chanResultsDirAndFile)
	wg.Add(1)
	go core.Transmit4into1chan(&mu, &wg, chanResultsHttp, chanResults, &count, maxGoroutines)
	wg.Add(1)
	go core.Transmit4into1chan(&mu, &wg, chanResultsDNS, chanResults, &count, maxGoroutines)
	wg.Add(1)
	go core.Transmit4into1chan(&mu, &wg, chanResultsAmass, chanResults, &count, maxGoroutines)
	wg.Add(1)
	go core.Transmit4into1chan(&mu, &wg, chanResultsSubfinder, chanResults, &count, maxGoroutines)

	wg.Add(1)
	go func() {
		core.ScanDomain(ctx, workDirectory, domainName, chanResults)
		wg.Done()
	}()

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("\nComplete all missions with time ", elapsed)
}
