package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
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

func InformationOfAllSubDomain(wg1 *sync.WaitGroup, subDomainChan chan string, infoAllSubDomain map[string]data.InfoSubDomain) {
	defer wg1.Done()
	var wg sync.WaitGroup
	const maxGoroutines = 10 // Limit the number of concurrent goroutines

	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go func() {
			for subDomain := range subDomainChan {
				var wgsubDomain sync.WaitGroup
				infoSubDomain := infoAllSubDomain[subDomain]
				wgsubDomain.Add(1)
				go dns.GetIpAndcName(&wgsubDomain, subDomain, &infoSubDomain) //Get Ip,cName

				wgsubDomain.Add(1)
				go tech.HttpxSimple(&wgsubDomain, subDomain, &infoSubDomain) //Get tech,title,status

				wgsubDomain.Wait()
				infoAllSubDomain[subDomain] = infoSubDomain //Assignment new item into map
			}
			wg.Done()

		}()
	}

	wg.Wait()
}

func ScanDomain(ctx context.Context, workDirectory string, rootDomain string) {
	start := time.Now()
	fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", "ScanDomain", "Running....")

	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex
	subDomainsFile := make(chan string, 50)
	subDomainChan := make(chan string, 50)
	// Create map to store unique line
	subDomainsMap := make(map[string]bool)

	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainBruteForceDNS.txt", subDomainsFile, &count, &mu, 4)
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainBruteForceHttp.txt", subDomainsFile, &count, &mu, 4)
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainOSINTAmass.txt", subDomainsFile, &count, &mu, 4)
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, workDirectory+"/data/output/DomainOSINTSubfinder.txt", subDomainsFile, &count, &mu, 4)

	wg.Add(1)
	go func() {
		for subDomain := range subDomainsFile {
			line := strings.TrimSpace(subDomain)
			//Add new line if don"t have
			if line != "" {
				subDomainsMap[line] = true
			}
		}
		wg.Done()
	}()

	wg.Wait()
	// create slice containing the key
	var subDomains []string
	for subDomainMap := range subDomainsMap {
		subDomains = append(subDomains, subDomainMap)
	}

	// Sort slice keys
	sort.Strings(subDomains)
	var wg1 sync.WaitGroup
	infoDomain := data.ListDomain[rootDomain]

	if infoDomain.SubDomain == nil {
		infoDomain.SubDomain = make(map[string]data.InfoSubDomain)
	}
	dns.DNS(rootDomain, &infoDomain) //Get information dns of rootdomain

	data.ListDomain[rootDomain] = infoDomain

	wg1.Add(1)
	go func() {
		for _, subDomain := range subDomains {
			subDomainChan <- subDomain
		}
		close(subDomainChan)
		wg1.Done()
	}()
	wg1.Add(1)
	go InformationOfAllSubDomain(&wg1, subDomainChan, infoDomain.SubDomain)

	wg1.Wait()

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
	elapsed := time.Since(start)
	select {
	case <-ctx.Done():
		// If a signal is received from the context
		fmt.Fprintf(os.Stderr, "[*] %-22s : %s%v\n", "ScanDomain", red("Finished due to cancellation in "), elapsed)
	default:
		// If there is no cancel signal, take another action
		fmt.Fprintf(os.Stderr, "[*] %-22s : %s%v\n", "ScanDomain", green("Finished successfully in "), elapsed)
	}
}
