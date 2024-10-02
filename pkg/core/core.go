package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"recon/pkg/collector/dir"
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
	green = color.New(color.FgHiGreen).SprintFunc()
	red   = color.New(color.FgHiRed).SprintFunc()
)

func Core(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, domainName string, workDirectory string, nameFunc string, chanResults chan string) {
	wg.Add(1)
	go func() {
		start := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", nameFunc, "Running....")

		if nameFunc == "DomainBruteForceHttp" {
			domain.DomainBruteForceHttp(domainName, workDirectory+"/pkg/data/input/subdomains-top1mil-110000.txt", chanResults)
		} else if nameFunc == "DomainBruteForceDNS" {
			domain.DomainBruteForceDNS(ctx, cancel, domainName, workDirectory+"/pkg/data/input/subdomains-top1mil-110000.txt", chanResults) //combined_subdomains
		} else if nameFunc == "DomainOSINTAmass" {
			domain.DomainOSINTAmass(ctx, cancel, domainName, workDirectory, chanResults)
		} else if nameFunc == "DomainOSINTSubfinder" {
			domain.DomainOSINTSubfinder(ctx, cancel, domainName, workDirectory, chanResults)
		} else if nameFunc == "DirAndFileBruteForce" {
			dir.DirAndFileBruteForce(ctx, domainName, workDirectory+"/pkg/data/input/common.txt")
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

func ScanDomain(ctx context.Context, wgScanDomain *sync.WaitGroup, workDirectory string, rootDomain string, chanResults chan string) {
	defer wgScanDomain.Done()

	start := time.Now()
	fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", "ScanDomain", "Running....")

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
		close(chanResults) //Close the results channel after stop context
	}
	mu.Unlock()
}

// Cấu trúc dữ liệu InfoWeb, InfoSubDomain, InfoDomain giống với file JSON của bạn
type InfoWeb struct {
	TechnologyDetails map[string]interface{} `json:"technologydetails"`
	FireWall          string                 `json:"firewall"`
	Status            string                 `json:"status"`
	Title             string                 `json:"title"`
}

type InfoSubDomain struct {
	NameSubDomain  string             `json:"namesubdomain"`
	Ips            []string           `json:"ips"`
	PortAndService map[string]string  `json:"portsandservice"`
	Os             []string           `json:"os"`
	HttpOrHttps    map[string]InfoWeb `json:"httporhttps"`
	CName          []string           `json:"cname"`
}

type InfoDomain struct {
	MXRecords  []string                 `json:"mxrecords"`
	NSRecords  []string                 `json:"nsrecords"`
	SOARecords []string                 `json:"soarecords"`
	TXTRecords []string                 `json:"txtrecords"`
	SubDomain  map[string]InfoSubDomain `json:"subdomain"`
}

var ListDomain map[string]InfoDomain

// Function to read JSON file
func loadJSONFile(fileName string) error {
	//Open JSON file
	jsonFile, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("error open file: %v", err)
	}
	defer jsonFile.Close()

	// Read content file
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return fmt.Errorf("error read file: %v", err)
	}

	// Decode JSON data into map
	err = json.Unmarshal(byteValue, &ListDomain)
	if err != nil {
		return fmt.Errorf("error decode JSON: %v", err)
	}

	return nil
}

// Handler for endpoint returns JSON data
func jsonHandler(w http.ResponseWriter, r *http.Request) {
	// Set headers for response
	w.Header().Set("Content-Type", "application/json")

	// Convert ListDomain data to JSON
	jsonData, err := json.MarshalIndent(ListDomain, "", "  ")
	if err != nil {
		http.Error(w, "Cannot convert data to JSON", http.StatusInternalServerError)
		return
	}

	// Sen data JSON to client
	w.Write(jsonData)
}

func DashBoard(workDirectory string) {
	err := loadJSONFile(workDirectory + "list_domain.json")
	if err != nil {
		log.Fatalf("error load file: %v", err)
	}

	// Initialize HTTP server on port 8080
	http.HandleFunc("/data", jsonHandler)

	fmt.Println("Server run on http://localhost:8080/data")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Not run server: %v", err)
	}
}
