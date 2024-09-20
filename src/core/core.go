package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"recon/collector/dir"
	"recon/collector/dns"
	"recon/collector/domain"
	"recon/collector/tech"
	data "recon/data/type"
	"recon/utils"

	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	// Colors used to ease the reading of program output
	green = color.New(color.FgHiGreen).SprintFunc()
	red   = color.New(color.FgHiRed).SprintFunc()
)

func Core(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, domainName string, workDirectory string, nameFunc string) {
	wg.Add(1)
	go func() {
		start := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", nameFunc, "Running....")

		if nameFunc == "DomainBruteForceHttp" {
			domain.DomainBruteForceHttp(domainName, workDirectory+"/data/input/subdomains-top1mil-110000.txt", workDirectory)
		} else if nameFunc == "DomainBruteForceDNS" {
			domain.DomainBruteForceDNS(ctx, cancel, domainName, workDirectory+"/data/input/subdomains-top1mil-110000.txt", workDirectory) //combined_subdomains
		} else if nameFunc == "DomainOSINTAmass" {
			domain.DomainOSINTAmass(ctx, cancel, domainName, workDirectory)
		} else if nameFunc == "DomainOSINTSubfinder" {
			domain.DomainOSINTSubfinder(ctx, cancel, domainName, workDirectory)
		} else if nameFunc == "DirAndFileBruteForce" {
			dir.DirAndFileBruteForce(ctx, domainName, workDirectory+"/data/input/common.txt", workDirectory)
		}

		elapsed := time.Since(start)

		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-22s : %s%v\n", nameFunc, red("Finished due to cancellation in "), elapsed)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-22s : %s%v\n", nameFunc, green("Finished successfully in "), elapsed)
		}
		wg.Done()
	}()
}

func AllOfInformationOfDomain(wg1 *sync.WaitGroup, ctx context.Context, workDirectory string, domainsChan chan string) {
	defer wg1.Done()
	var wg sync.WaitGroup
	const maxGoroutines = 20 // Limit the number of concurrent goroutines
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go func() {
			for domain := range domainsChan {
				var wgDomain sync.WaitGroup
				infoDomain := data.ListDomain[domain]

				wgDomain.Add(1)
				go dns.GetIpAndcName(&wgDomain, domain, &infoDomain) //Get Ip,cName

				wgDomain.Add(1)
				go tech.HttpxSimple(&wgDomain, domain, &infoDomain) //Get tech,title,status

				wgDomain.Wait()
				data.ListDomain[domain] = infoDomain //Assignment new item into map
			}
			wg.Done()
		}()
	}
	wg.Wait()
	// Convert ListDomain to JSON and write to file
	file, err := os.Create("list_domain.json")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Set indentation for readability
	err = encoder.Encode(data.ListDomain)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
	}
	//fmt.Println(data.ListDomain)
}

func ScanDomain(ctx context.Context, workDirectory string, Domain string) map[string]bool {
	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex
	outputChan := make(chan string, 50)
	inputChan := make(chan string, 50)
	// Create map to store unique line
	uniqueLines := make(map[string]bool)

	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainBruteForceDNS.txt", outputChan, &count, &mu, 4)
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainBruteForceHttp.txt", outputChan, &count, &mu, 4)
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainOSINTAmass.txt", outputChan, &count, &mu, 4)
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainOSINTSubfinder.txt", outputChan, &count, &mu, 4)

	wg.Add(1)
	go func() {
		for domain := range outputChan {
			line := strings.TrimSpace(domain)
			//Add new line if don"t have
			if line != "" {
				uniqueLines[line] = true
			}
		}
		wg.Done()
	}()

	wg.Wait()
	var wg1 sync.WaitGroup
	wg1.Add(1)
	go func() {
		for domain := range uniqueLines {
			inputChan <- domain
		}
		close(inputChan)
		wg1.Done()
	}()
	wg1.Add(1)
	go AllOfInformationOfDomain(&wg1, ctx, workDirectory, inputChan)
	wg1.Wait()
	return uniqueLines
}
