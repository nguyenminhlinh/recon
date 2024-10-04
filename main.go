package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"recon/pkg/core"
	"recon/pkg/utils"
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

	if !utils.HasRootPrivilege() {
		println("This script must be run as root")
		return
	}

	var domainName string

	var dashBoard bool
	flag.BoolVar(&dashBoard, "dash-board", false, "show dashboard Grafana")
	var report bool
	flag.BoolVar(&report, "report", false, "show report Latex")

	flag.Parse()

	if flag.NArg() > 0 {
		// fetch for a single domain
		domainName = flag.Arg(0)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//utils.CancelRun(cancel)
	utils.StopRun()

	workDirectory := utils.Getwd()

	const maxChanResults = 100 // Limit the number of elements in chan results
	const maxChanResult = 50   // Limit the number of elements in chan results

	chanResults := make(chan string, maxChanResults)
	chanResultsDNS := make(chan string, maxChanResult)
	chanResultsHttp := make(chan string, maxChanResult)
	chanResultsAmass := make(chan string, maxChanResult)
	chanResultsSubfinder := make(chan string, maxChanResult)

	// Get command from console
	// if len(os.Args) < 2 {
	// 	fmt.Println("Usage: go run . <domain>")
	// 	os.Exit(1)
	// }

	// domainName := os.Args[1]

	fmt.Fprintf(os.Stderr, "%s\n       %+60s\n%s\n", BANNER_HEADER, "Made by MinhLinh", BANNER_SEP)
	fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", "Scanning target", domainName)

	core.Core(ctx, cancel, &mu, &wg, domainName, workDirectory, "DomainBruteForceHttp", chanResultsHttp, chanResults)
	core.Core(ctx, cancel, &mu, &wg, domainName, workDirectory, "DomainBruteForceDNS", chanResultsDNS, chanResults)
	core.Core(ctx, cancel, &mu, &wg, domainName, workDirectory, "DomainOSINTAmass", chanResultsAmass, chanResults)
	core.Core(ctx, cancel, &mu, &wg, domainName, workDirectory, "DomainOSINTSubfinder", chanResultsSubfinder, chanResults)

	wg.Add(1)
	go core.ScanInfoDomain(ctx, &wg, workDirectory, domainName, chanResults)

	wg.Wait()
	if dashBoard {
		core.DashBoard(workDirectory, ctx)
	}

	if report {
		core.Report(workDirectory)
	}

	elapsed := time.Since(start)
	fmt.Println("\nComplete all missions with time ", elapsed)
}
