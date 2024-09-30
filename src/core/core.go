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
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	// Colors used to ease the reading of program output
	green = color.New(color.FgHiGreen).SprintFunc()
	red   = color.New(color.FgHiRed).SprintFunc()
)

func Core(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, domainName string, workDirectory string, nameFunc string, chanResults chan string) {
	wg.Add(1)
	go func() {
		start := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", nameFunc, "Running....")

		if nameFunc == "DomainBruteForceHttp" {
			domain.DomainBruteForceHttp(domainName, workDirectory+"/data/input/subdomains-top1mil-110000.txt", chanResults)
		} else if nameFunc == "DomainBruteForceDNS" {
			domain.DomainBruteForceDNS(ctx, cancel, domainName, workDirectory+"/data/input/subdomains-top1mil-110000.txt", chanResults) //combined_subdomains
		} else if nameFunc == "DomainOSINTAmass" {
			domain.DomainOSINTAmass(ctx, cancel, domainName, workDirectory, chanResults)
		} else if nameFunc == "DomainOSINTSubfinder" {
			domain.DomainOSINTSubfinder(ctx, cancel, domainName, workDirectory, chanResults)
		} else if nameFunc == "DirAndFileBruteForce" {
			dir.DirAndFileBruteForce(ctx, domainName, workDirectory+"/data/input/common.txt")
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

func ScanDomain(ctx context.Context, workDirectory string, rootDomain string, chanResults chan string) {
	start := time.Now()
	fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", "ScanDomain", "Running....")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var subDomainsMap sync.Map // Create map to store unique line

	//subDomainsMap := make(map[string]bool)
	subDomainChan := make(chan string, 500)
	infoDomain := data.ListDomain[rootDomain]

	if infoDomain.SubDomain == nil {
		infoDomain.SubDomain = make(map[string]data.InfoSubDomain)
	}
	dns.DNS(rootDomain, &infoDomain) //Get information dns of rootdomain

	data.ListDomain[rootDomain] = infoDomain
	wg.Add(1)
	go func() {
		for subDomain := range chanResults {
			line := strings.TrimSpace(subDomain)
			line = strings.ToLower(line)
			if line != "" {
				if _, exists := subDomainsMap.Load(line); !exists { //Add new line if don"t have
					subDomainsMap.Store(line, true)
					subDomainChan <- line
					fmt.Printf("Added: %s\n", line)
				}
			}
			fmt.Println("chanResults", len(chanResults))
			fmt.Println("subDomainChan", len(subDomainChan))
		}
		close(subDomainChan)
		fmt.Println("Added done")
		wg.Done()
	}()
	// for subDomain := range chanResults {
	// 	line := strings.TrimSpace(subDomain)
	// 	line = strings.ToLower(line)
	// 	//Add new line if don"t have
	// 	if line != "" {
	// 		subDomainsMap[line] = true
	// 		fmt.Println(line)
	// 	}
	// }

	// wg.Add(1)
	// go func() {
	// 	for subDomain := range subDomainsMap {
	// 		subDomainChan <- subDomain
	// 	}
	// 	wg.Done()
	// 	close(subDomainChan)
	// }()
	// wg.Add(1)
	// go func() {
	// 	subDomainsMap.Range(func(key, value interface{}) bool {
	// 		//fmt.Printf("Key: %s, Value: %v\n", key, value)
	// 		subDomainChan <- key.(string)
	// 		return true // Trả về true để tiếp tục duyệt
	// 	})
	// 	wg.Done()
	// 	close(subDomainChan)
	// }()

	wg.Add(1)
	go InformationOfAllSubDomain(ctx, &wg, subDomainChan, infoDomain.SubDomain, workDirectory, &mu)

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

func InformationOfAllSubDomain(ctx context.Context, wg1 *sync.WaitGroup, subDomainChan chan string, infoAllSubDomain map[string]data.InfoSubDomain, workDirectory string, mu *sync.Mutex) {
	defer wg1.Done()
	var wg sync.WaitGroup
	const maxGoroutines = 20
	cloudflareIPs, incapsulaIPs, awsCloudFrontIPs, gcoreIPs, fastlyIPs := dns.GetIntermediaryIpRange()
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go func() {
			for subDomain := range subDomainChan {
				var wgsubDomain sync.WaitGroup
				mu.Lock() // Lock map before accessing it
				infoSubDomain, exists := infoAllSubDomain[subDomain]
				mu.Unlock()
				if !exists {
					infoSubDomain = data.InfoSubDomain{
						Ips:            []string{},
						PortAndService: make(map[string]string),
						Os:             []string{},
						HttpOrHttps:    make(map[string]data.InfoWeb),
						CName:          []string{},
					}
				}

				wgsubDomain.Add(1)
				go dns.GetIpAndcName(ctx, &wgsubDomain, subDomain, &infoSubDomain, &cloudflareIPs, &incapsulaIPs, &awsCloudFrontIPs, &gcoreIPs, &fastlyIPs, workDirectory)

				wgsubDomain.Add(1)
				go tech.HttpxSimple(&wgsubDomain, subDomain, &infoSubDomain)

				wgsubDomain.Wait()

				mu.Lock() // Lock map before updating it
				infoAllSubDomain[subDomain] = infoSubDomain
				mu.Unlock()
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func Transmit4into1chan(mu *sync.Mutex, wg *sync.WaitGroup, inputChan chan string, chanResults chan string, count *int, maxGoroutines int) {
	defer wg.Done()
	for input := range inputChan {
		chanResults <- input
	}
	mu.Lock()
	(*count)++
	if *count == maxGoroutines {
		for len(inputChan) > 0 {
			<-inputChan // Read and skip data until the channel is empty
		}
		fmt.Println("close chanResults")
		close(chanResults) //Close the results channel after stop context
	}
	mu.Unlock()
}
