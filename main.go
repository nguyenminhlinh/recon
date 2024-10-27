package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"recon/pkg/core"
	data "recon/pkg/data/type"
	"recon/pkg/utils"
	"sync"
	"time"
)

func main() {
	if !utils.HasRootPrivilege() {
		println("This script must be run as root")
		return
	}

	var domainName string

	//options scan
	var dashBoard bool
	flag.BoolVar(&dashBoard, "dash-board", false, "show dashboard Grafana")
	var report bool
	flag.BoolVar(&report, "report", false, "show report Latex")

	//type scan
	var typeScan int
	var basic bool
	flag.BoolVar(&basic, "basic", false, "run with speed fast and recive less infomation")
	var moderate bool
	flag.BoolVar(&moderate, "moderate", false, "run with speed moderate and recive moderate infomation")
	var comprehensive bool
	flag.BoolVar(&comprehensive, "comprehensive", false, "run with speed slow and recive more infomation")

	flag.Parse()

	if flag.NArg() > 0 {
		// fetch for a single domain
		domainName = flag.Arg(0)
	} else {
		fmt.Println("Please run with command: go run . [type scan] [option] <domain> ")
	}

	// Check if the user has selected more than 1 flag
	selectedFlags := 0
	if basic {
		selectedFlags++
	}
	if moderate {
		selectedFlags++
	}
	if comprehensive {
		selectedFlags++
	}

	if selectedFlags != 1 {
		fmt.Println("Error scan type: You must specify exactly one of the following flags: --basic, --moderate, or --comprehensive.")
		os.Exit(1)
	}

	if basic {
		typeScan = 1
	} else if moderate {
		typeScan = 2
	} else if comprehensive {
		typeScan = 3
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

	infoSubDomainChan := make(chan data.InfoSubDomain)
	var flag [5]int
	var elapsed [5]time.Duration
	core.Core(&infoSubDomainChan, ctx, cancel, &mu, &wg, domainName, workDirectory, "Domain BruteForce Over Http", chanResultsHttp, chanResults, typeScan, &flag, &elapsed, 0)
	core.Core(&infoSubDomainChan, ctx, cancel, &mu, &wg, domainName, workDirectory, "Domain BruteForce Over DNS", chanResultsDNS, chanResults, typeScan, &flag, &elapsed, 1)
	core.Core(&infoSubDomainChan, ctx, cancel, &mu, &wg, domainName, workDirectory, "Domain OSINT Amass", chanResultsAmass, chanResults, typeScan, &flag, &elapsed, 2)
	core.Core(&infoSubDomainChan, ctx, cancel, &mu, &wg, domainName, workDirectory, "Domain OSINT Subfinder", chanResultsSubfinder, chanResults, typeScan, &flag, &elapsed, 3)

	wg.Add(1)
	go core.ScanInfoDomain(ctx, &wg, workDirectory, domainName, chanResults, typeScan, &infoSubDomainChan, &flag, &elapsed, 4)

	wg.Add(1)
	go core.Display(&wg, &infoSubDomainChan, &flag, &elapsed, domainName, dashBoard, report, typeScan)

	wg.Wait()

	if dashBoard {
		core.DashBoard(workDirectory, ctx)
	}

	if report {
		core.Report(workDirectory)
	}
}
