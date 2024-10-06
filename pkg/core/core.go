package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"recon/pkg/collector/dns"
	"recon/pkg/collector/domain"
	"recon/pkg/collector/tech"
	data "recon/pkg/data/type"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	// Colors used to ease the reading of program output
	green            = color.New(color.FgHiGreen).SprintFunc()
	red              = color.New(color.FgHiRed).SprintFunc()
	countToCloseChan = 0
	maxGoroutines    = 4
	wordList         = []string{"/pkg/data/input/subdomains-top1mil-20000.txt", "/pkg/data/input/subdomains-top1mil-110000.txt", "/pkg/data/input/combined_subdomains_653919.txt"}
)

func Core(ctx context.Context, cancel context.CancelFunc, mu *sync.Mutex, wg *sync.WaitGroup, domainName string, workDirectory string, nameFunc string, chanSingle chan string, chanResults chan string, typeScan int) {
	wg.Add(1)
	go func() {
		start := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", nameFunc, "Running....")

		if nameFunc == "Domain BruteForce Over Http" {
			domain.DomainBruteForceHttp(domainName, workDirectory+wordList[typeScan-1], chanSingle)
		} else if nameFunc == "Domain BruteForce Over DNS" {
			domain.DomainBruteForceDNS(ctx, cancel, domainName, workDirectory+wordList[typeScan-1], chanSingle)
		} else if nameFunc == "Domain OSINT Amass" {
			domain.DomainOSINTAmass(ctx, cancel, domainName, workDirectory, chanSingle, typeScan)
		} else if nameFunc == "Domain OSINT Subfinder" {
			domain.DomainOSINTSubfinder(ctx, cancel, domainName, workDirectory, chanSingle)
		}

		elapsed := time.Since(start)

		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", nameFunc, red("Finished due to cancellation in "), elapsed)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", nameFunc, green("Finished successfully in "), elapsed)
		}
		wg.Done()
	}()

	wg.Add(1)
	go Transmit4into1chan(mu, wg, chanSingle, chanResults, &countToCloseChan, maxGoroutines)
}

func ScanInfoDomain(ctx context.Context, wgScanDomain *sync.WaitGroup, workDirectory string, rootDomain string, chanResults chan string, typeScan int) {
	defer wgScanDomain.Done()

	start := time.Now()
	fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", "ScanDomain", "Running....")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var subDomainsMap sync.Map // Create map to store unique line

	subDomainChan := make(chan string, 200)
	var buffer []string
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
					select {
					case subDomainChan <- line: //Add if subDomainChan have place
					default: // If subDomainChan then add to buffer
						buffer = append(buffer, line)
					}
				}
			}
		}

		for len(buffer) > 0 { //If buffer not empty then push element to subDomainChan
			subDomainChan <- buffer[0] // Push from slice to chan
			buffer = buffer[1:]        // Delete element has pushed to chan
		}
		close(subDomainChan)
		wg.Done()
	}()

	wg.Add(1)
	go InformationOfAllSubDomain(ctx, &wg, subDomainChan, infoDomain.SubDomain, workDirectory, &mu, typeScan)

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
		fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", "ScanDomain", red("Finished due to cancellation in "), elapsed)
	default:
		// If there is no cancel signal, take another action
		fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", "ScanDomain", green("Finished successfully in "), elapsed)
	}
}

func InformationOfAllSubDomain(ctx context.Context, wg1 *sync.WaitGroup, subDomainChan chan string, infoAllSubDomain map[string]data.InfoSubDomain, workDirectory string, mu *sync.Mutex, typeScan int) {
	defer wg1.Done()

	var wg sync.WaitGroup
	const maxGoroutines = 30
	cloudflareIPs, incapsulaIPs, awsCloudFrontIPs, gcoreIPs, fastlyIPs, googleIPS := dns.GetIntermediaryIpRange()

	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go func(countWorker int) {
			for subDomain := range subDomainChan {
				var wgsubDomain sync.WaitGroup

				mu.Lock() // Lock map before accessing it
				infoSubDomain, exists := infoAllSubDomain[subDomain]
				mu.Unlock()

				if !exists {
					infoSubDomain = data.InfoSubDomain{
						NameSubDomain:  "",
						Ips:            []string{},
						PortAndService: make(map[string]string),
						Os:             []string{},
						HttpOrHttps:    make(map[string]data.InfoWeb),
						CName:          []string{},
					}
				}
				infoSubDomain.NameSubDomain = subDomain
				wgsubDomain.Add(1)
				go dns.GetIpAndcName(countWorker, ctx, &wgsubDomain, subDomain, &infoSubDomain, &cloudflareIPs, &incapsulaIPs, &awsCloudFrontIPs, &gcoreIPs, &fastlyIPs, &googleIPS, workDirectory)

				wgsubDomain.Add(1)
				go tech.HttpxSimple(ctx, &wgsubDomain, subDomain, &infoSubDomain, typeScan)

				wgsubDomain.Wait()

				mu.Lock() // Lock map before updating it
				infoAllSubDomain[subDomain] = infoSubDomain
				mu.Unlock()
			}
			wg.Done()
		}(i)
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
		close(chanResults) //Close the results channel after stop context
	}
	mu.Unlock()
}

// Function to read JSON file
func loadJSONFile(fileName string) {
	//Open JSON file
	jsonFile, err := os.Open(fileName)
	if err != nil {
		fmt.Println("error open file:", err)
	}
	defer jsonFile.Close()

	// Read content file
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("error read file:", err)
	}

	// Decode JSON data into map
	err = json.Unmarshal(byteValue, &data.ListDomain)
	if err != nil {
		fmt.Println("error decode JSON:", err)
	}
}

// Handler for endpoint returns JSON data
func jsonHandler(w http.ResponseWriter, r *http.Request) {
	// Set headers for response
	w.Header().Set("Content-Type", "application/json")

	// Convert ListDomain data to JSON
	jsonData, err := json.MarshalIndent(data.ListDomain, "", "  ")
	if err != nil {
		http.Error(w, "Cannot convert data to JSON", http.StatusInternalServerError)
		return
	}

	// Sen data JSON to client
	w.Write(jsonData)
}

func DashBoard(workDirectory string, ctx context.Context) {
	loadJSONFile(workDirectory + "/list_domain.json")

	// Initialize HTTP server on port 8080
	http.HandleFunc("/data", jsonHandler)

	go func() {
		fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", "Server data run on", green("http://localhost:8080/data"))
		if err := http.ListenAndServe(":8080", nil); err != nil {
			fmt.Println("Not run server: ", err)
		}
	}()

	// wg.Add(1)
	// go func() {
	// 	fmt.Fprintf(os.Stderr, "[*] %-22s : %s", "Server Grafana run on", green("http://localhost:3000/goto/_HLZmhkNg?orgId=1"))
	// 	fmt.Println()
	// 	exePath := workDirectory + "/grafana-11.2.1.windows-amd64/grafana-v11.2.1/bin/grafana-server.exe"
	// 	homePath := workDirectory + "/grafana-11.2.1.windows-amd64/grafana-v11.2.1"

	// 	cmd := exec.Command(exePath, "--homepath", homePath)
	// 	// Execute the command and get the output
	// 	_, err := cmd.Output()
	// 	if err != nil {
	// 		fmt.Println("Error when run file .exe: ", err)
	// 	}
	// 	wg.Done()
	// }()
}

func Report(workDirectory string) {

}
