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
	green            = color.New(color.FgGreen).SprintFunc()
	red              = color.New(color.FgRed).SprintFunc()
	blue             = color.New(color.FgBlue).SprintFunc()
	yellow           = color.New(color.FgYellow).SprintFunc()
	cyan             = color.New(color.FgCyan).SprintFunc()
	countToCloseChan = 0
	maxGoroutines    = 4
	wordList         = []string{"/pkg/data/input/subdomains-top1mil-20000.txt", "/pkg/data/input/subdomains-top1mil-110000.txt", "/pkg/data/input/combined_subdomains_653919.txt"}
	nameFunc         = []string{"Domain BruteForce Over Http", "Domain BruteForce Over DNS", "Domain OSINT Amass", "Domain OSINT Subfinder", "Collect all domain information"}
	typeScan         = []string{"Basic", "Moderate", "Comprehensive"}
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

func Core(ctx context.Context, cancel context.CancelFunc, mu *sync.Mutex, wg *sync.WaitGroup, domainName string, workDirectory string, nameFunc string, chanSingle chan string, chanResults chan string, typeScanInt int, flag *[5]int, elapsed *[5]time.Duration, stt int) {
	(*flag)[stt] = 0
	wg.Add(1)
	go func(flag *[5]int, elapsed *[5]time.Duration, stt int) {
		start := time.Now()

		if nameFunc == "Domain BruteForce Over Http" {
			domain.DomainBruteForceHttp(domainName, workDirectory+wordList[typeScanInt-1], chanSingle)
		} else if nameFunc == "Domain BruteForce Over DNS" {
			domain.DomainBruteForceDNS(ctx, cancel, domainName, workDirectory+wordList[typeScanInt-1], chanSingle)
		} else if nameFunc == "Domain OSINT Amass" {
			domain.DomainOSINTAmass(ctx, cancel, domainName, workDirectory, chanSingle, typeScanInt)
		} else if nameFunc == "Domain OSINT Subfinder" {
			domain.DomainOSINTSubfinder(ctx, cancel, domainName, workDirectory, chanSingle)
		}

		(*elapsed)[stt] = time.Since(start)
		select {
		case <-ctx.Done():
			(*flag)[stt] = 1 // If a signal is received from the context
		default:
			(*flag)[stt] = 2 // If there is no cancel signal, take another action
		}
		wg.Done()
	}(flag, elapsed, stt)

	wg.Add(1)
	go Transmit4into1chan(mu, wg, chanSingle, chanResults, &countToCloseChan, maxGoroutines)

}

func ScanInfoDomain(ctx context.Context, wgScanDomain *sync.WaitGroup, workDirectory string, rootDomain string, chanResults chan string, typeScanInt int, infoSubDomainChan *chan data.InfoSubDomain, flag *[5]int, elapsed *[5]time.Duration, stt int) {
	(*flag)[stt] = 0
	defer wgScanDomain.Done()

	start := time.Now()

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
	go InformationOfAllSubDomain(ctx, &wg, subDomainChan, infoDomain.SubDomain, workDirectory, &mu, typeScanInt, infoSubDomainChan)

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

	(*elapsed)[stt] = time.Since(start)

	select {
	case <-ctx.Done():
		(*flag)[stt] = 1 // If a signal is received from the context
	default:
		(*flag)[stt] = 2 // If there is no cancel signal, take another action
	}

	for {
		if flag[0] == 2 && flag[1] == 2 && flag[2] == 2 && flag[3] == 2 {
			*infoSubDomainChan <- data.InfoSubDomain{}
			close(*infoSubDomainChan)
			break
		}
	}

}

func InformationOfAllSubDomain(ctx context.Context, wg1 *sync.WaitGroup, subDomainChan chan string, infoAllSubDomain map[string]data.InfoSubDomain, workDirectory string, mu *sync.Mutex, typeScanInt int, infoSubDomainChan *chan data.InfoSubDomain) {
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
				go tech.HttpxSimple(ctx, &wgsubDomain, subDomain, &infoSubDomain, typeScanInt)

				wgsubDomain.Wait()

				mu.Lock() // Lock map before updating it
				infoAllSubDomain[subDomain] = infoSubDomain
				*infoSubDomainChan <- infoSubDomain
				mu.Unlock()
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func splitIntoChunks(s string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		// Tính toán chiều dài cho chunk hiện tại
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end]) // Thêm chunk vào danh sách
	}
	return chunks
}

func Display(wg *sync.WaitGroup, infoSubDomainChan *chan data.InfoSubDomain, flag *[5]int, elapsed *[5]time.Duration, domainName string, dashBoard bool, report bool, typeScanInt int) {
	defer wg.Done()

	var numberOrder int
	var options string

	if report {
		options = options + "ReportLatex "
	}

	if dashBoard {
		options = options + "DashBoard "
	}

	fmt.Fprintf(os.Stderr, "%s\n       %+60s\n%s\n", BANNER_HEADER, cyan("Made by MinhLinh"), BANNER_SEP)
	fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", "Scanning target", blue(domainName))
	if dashBoard || report {
		fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", "Options", options)
	}
	fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", "Scan type", typeScan[typeScanInt-1])

	for i := 0; i < 5; i++ {
		fmt.Fprintf(os.Stderr, "[*] %-30s : %s%s\n", nameFunc[i], "Start", yellow("..."))
	}
	head := "+------+--------------------------+--------------------------+--------+------+--------+--------+----------+---------+---------+\n"
	head += "|  NO. |        Sub Domain        |             IP           |  PORT  |  OS  |  TECH  |  LINK  |  STATUS  |  TITLE  |  CNAME  |\n"
	head += "+------+--------------------------+--------------------------+--------+------+--------+--------+----------+---------+---------+\n"
	fmt.Print(head)

	// Add rows
	for infoSubDomain := range *infoSubDomainChan {
		if infoSubDomain.NameSubDomain == "" {
			continue
		}
		numberOrder++
		var ips string
		var ports string
		var oss string
		var tech string
		var link string
		var status string
		var title string
		var cname string

		for _, ip := range infoSubDomain.Ips {
			ips = ips + ip + ","
		}
		if len(infoSubDomain.PortAndService) > 0 {
			ports = green("✔")
		} else {
			ports = red("✘")
		}
		if len(infoSubDomain.Os) > 0 {
			oss = green("✔")
		} else {
			oss = red("✘")
		}
		if len(infoSubDomain.CName) > 0 {
			cname = green("✔")
		} else {
			cname = red("✘")
		}
		for _, httpOrHttps := range infoSubDomain.HttpOrHttps {
			if len(httpOrHttps.TechnologyDetails) > 0 {
				tech = green("✔")
			} else {
				tech = red("✘")
			}
			if len(httpOrHttps.Link) > 0 {
				link = green("✔")
			} else {
				link = red("✘")
			}
			if len(httpOrHttps.Status) > 0 {
				status = green("✔")
			} else {
				status = red("✘")
			}
			if len(httpOrHttps.Title) > 0 {
				title = green("✔")
			} else {
				title = red("✘")
			}
		}
		var ip []string
		nameSubDomain := splitIntoChunks(infoSubDomain.NameSubDomain, 22)
		lengthNameSubDomain := len(nameSubDomain)
		if len(ips) != 0 {
			ip = strings.Split(ips[:len(ips)-1], ",")
			fmt.Fprintf(os.Stderr, "| %-4v | %-24s | %-24s | %-15s | %-13s | %-15s | %-15s | %-17s | %-16s | %-16s |\n", numberOrder, nameSubDomain[0], ip[0], ports, oss, tech, link, status, title, cname)
		} else {
			fmt.Fprintf(os.Stderr, "| %-4v | %-24s | %-24s | %-15s | %-13s | %-15s | %-15s | %-17s | %-16s | %-16s |\n", numberOrder, nameSubDomain[0], " ", ports, oss, tech, link, status, title, cname)
		}
		lengthIp := len(ip)
		if lengthNameSubDomain > lengthIp {
			for i := 1; i < lengthIp; i++ {
				fmt.Fprintf(os.Stderr, "| %-4v | %-24s | %-24s | %-6s | %-4s | %-6s | %-6s | %-8s | %-7s | %-7s |\n", " ", nameSubDomain[i], ip[i], " ", " ", " ", " ", " ", " ", " ")
			}
			if lengthIp == 0 {
				lengthIp = 1
			}
			for i := lengthIp; i < lengthNameSubDomain; i++ {
				fmt.Fprintf(os.Stderr, "| %-4v | %-24s | %-24s | %-6s | %-4s | %-6s | %-6s | %-8s | %-7s | %-7s |\n", " ", nameSubDomain[i], " ", " ", " ", " ", " ", " ", " ", " ")
			}
		} else if lengthNameSubDomain <= lengthIp {
			for i := 1; i < lengthNameSubDomain; i++ {
				fmt.Fprintf(os.Stderr, "| %-4v | %-24s | %-24s | %-6s | %-4s | %-6s | %-6s | %-8s | %-7s | %-7s |\n", " ", nameSubDomain[i], ip[i], " ", " ", " ", " ", " ", " ", " ")
			}

			for i := lengthNameSubDomain; i < lengthIp; i++ {
				fmt.Fprintf(os.Stderr, "| %-4v | %-24s | %-24s | %-6s | %-4s | %-6s | %-6s | %-8s | %-7s | %-7s |\n", " ", " ", ip[i], " ", " ", " ", " ", " ", " ", " ")
			}
		}
		fmt.Fprintf(os.Stderr, "| %-4v | %-24s | %-24s | %-6s | %-4s | %-6s | %-6s | %-8s | %-7s | %-7s |\n", " ", "", " ", " ", " ", " ", " ", " ", " ", " ")
		fmt.Print("+------+--------------------------+--------------------------+--------+------+--------+--------+----------+---------+---------+\n")
		// Add each row to the table

		for i := 0; i < 5; i++ {
			if (*flag)[i] == 1 {
				fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", nameFunc[i], red("Finished due to cancellation in "), (*elapsed)[i])
			}
			if (*flag)[i] == 2 {
				fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", nameFunc[i], green("Finished successfully in "), (*elapsed)[i])
			}
		}

		for i := 0; i < 5; i++ {
			if (*flag)[i] == 1 || (*flag)[i] == 2 {
				fmt.Print("\033[F")
			}
		}
		fmt.Print("\033[F")
	}
	fmt.Print("\033[B")
	for i := 0; i < 5; i++ {
		if (*flag)[i] == 1 {
			fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", nameFunc[i], red("Finished due to cancellation in "), (*elapsed)[i])
		}
		if (*flag)[i] == 2 {
			fmt.Fprintf(os.Stderr, "[*] %-30s : %s%v\n", nameFunc[i], green("Finished successfully in "), (*elapsed)[i])
		}
	}
	fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", "Data server run on", green("http://localhost:8080/data"))
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

	//go func() {
	// fmt.Fprintf(os.Stderr, "[*] %-30s : %s\n", "Server data run on", green("http://localhost:8080/data"))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Not run server: ", err)
	}
	//}()

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
