package domain

import (
	"context"
	"fmt"
	"log"
	"os"
	"recon/utils"
	"strconv"
	"sync"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/enum"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
)

const maxGoroutines = 10    // Limit the number of concurrent goroutines
const maxChanSemaphore = 10 // Limit the number of elements in the chan semaphore
const maxChanResults = 10   // Limit the number of elements in chan results

func FuffDomainHttp(domain string, wordlist string, WorkDirectory string) {
	//Using the wrong host to get length web content "C:/Users/minhl/recon/src/data/common.txt"
	lengthResponse := utils.LengthResponse(domain, "abcdefghiklm."+domain)
	utils.Ffuf(domain, strconv.Itoa(lengthResponse), WorkDirectory+"/data/output/FuffDomainHttp.json", "domain", true, 0, wordlist)
}

func dig(domain string, qtype uint16) []dns.RR {
	// Create a DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	// Select the DNS server to query
	dnsServer := "8.8.8.8:53" //Use Google DNS

	// Create a client to send DNS requests
	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	// Send DNS requests
	response, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		//	fmt.Printf("Error: %v at domain %s \n", err, domain)
		return []dns.RR{}
	}
	return response.Answer
	// // Check DNS status code (Rcode)
	// fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n", dns.RcodeToString[response.Rcode], response.Id)
	// fmt.Printf(";; query time: %v msec\n", rtt.Milliseconds())

	// // Print the response if the status is NOERROR
	// if response.Rcode == dns.RcodeSuccess {
	// 	for _, answer := range response.Answer {
	// 		fmt.Println(answer.String())
	// 	}
	// } else {
	// 	fmt.Printf("Query failed with status: %s\n", dns.RcodeToString[response.Rcode])
	// }
}

func checkDomain(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, domain string, count *int, mu *sync.Mutex) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done(): //If a cancel signal is received from context
			//fmt.Println("<-ctx.Done()")
			mu.Lock()
			(*count)++
			if *count == maxChanSemaphore {
				for len(semaphore) > 0 {
					<-semaphore // Read and skip data until the channel is empty
				}
				close(results) //Close the results channel after stop context
			}
			mu.Unlock()
			return
		default:
			subdomain, ok := <-semaphore
			if !ok {
				(*count)++
				if *count == maxChanSemaphore {
					for len(semaphore) > 0 {
						<-semaphore // Read and skip data until the channel is empty
					}
					close(results) //Close the results channel after the goroutines complete
				}
				//fmt.Println(*count)
				return
			} else {
				responseAnswer := dig(subdomain+"."+domain, dns.TypeA)
				//fmt.Println(responseAnswer, subdomain)
				if len(responseAnswer) != 0 {
					//fmt.Fprintf(os.Stdout, "Subdomain tồn tại:: %-35s \n", subdomain)
					results <- subdomain + "\n"
				}
			}
		}
	}
}

func BruteDomainDNS(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string, WorkDirectory string) {
	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex
	// Create semaphore channel to receive info from file and sen to checkDomain
	semaphore := make(chan string, maxChanSemaphore)
	// Create semaphore channel to receive info from checkDomain and send to writeFiles
	results := make(chan string, maxChanResults)

	// Start the goroutine to read the file into chan
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, wordlist, semaphore)

	// Start goroutines to check the domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(ctx, &wg, semaphore, results, domain, &count, &mu)
	}

	// Start the goroutine to write the results to the output file
	wg.Add(1)
	go utils.WriteFiles(ctx, &wg, results, WorkDirectory+"/data/output/BruteDomainDNS.txt")

	// Wait for all goroutines to complete
	wg.Wait()
}

func NewOutput(ctx context.Context, g *netmap.Graph, e *enum.Enumeration, filter *stringset.Set, since time.Time) []string {
	var output []string

	// Make sure a filter has been created
	if filter == nil {
		filter = stringset.New()
		defer filter.Close()
	}

	var assets []*types.Asset
	for _, atype := range []oam.AssetType{oam.FQDN, oam.IPAddress, oam.Netblock, oam.ASN} {
		if a, err := g.DB.FindByType(atype, since.UTC()); err == nil {
			assets = append(assets, a...)
		}
	}
	start := e.Config.CollectionStartTime.UTC()
	for _, from := range assets {
		fromstr := fmt.Sprintf("%v", from.Asset.AssetType()) + "" + fmt.Sprintf("%v", from.Asset)
		if rels, err := g.DB.OutgoingRelations(from, start); err == nil {
			for _, rel := range rels {
				lineid := from.ID + rel.ID + rel.ToAsset.ID
				if filter.Has(lineid) {
					continue
				}
				if to, err := g.DB.FindById(rel.ToAsset.ID, start); err == nil {
					tostr := fmt.Sprintf("%v", to.Asset.AssetType()) + " " + fmt.Sprintf("%v", to.Asset)
					output = append(output, fmt.Sprintf("%s %s %s %s %s", fromstr, "-->", rel.Type, "-->", tostr))
					filter.Insert(lineid)
				}
			}
		}
	}

	return output
}

func processOutput(ctx context.Context, g *netmap.Graph, e *enum.Enumeration, outputs chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(outputs)

	// This filter ensures that we only get new names
	known := stringset.New()
	defer known.Close()

	// The function that obtains output from the enum and puts it on the channel
	extract := func(since time.Time) {
		for _, output := range NewOutput(ctx, g, e, known, since) {
			outputs <- output + "\n"
		}
	}

	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	last := e.Config.CollectionStartTime
	for {
		select {
		case <-ctx.Done():
			extract(last)
			return
		case <-t.C:
			next := time.Now()
			extract(last)
			t.Reset(10 * time.Second)
			last = next
		}
	}
}

func AmassDomainOSINT(ctx context.Context, cancel context.CancelFunc, domain string, WorkDirectory string) {
	// Create configuration for Amass
	cfg := config.NewConfig()

	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(WorkDirectory+"/data/output", WorkDirectory+"/data/input/config.yaml", cfg); err != nil {
		log.Fatalf("Failed to configuration file: %v", err)
	}
	cfg.AddDomain(domain) // Add domains to check

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		log.Fatalf("Failed to create system: %v", err)
	}
	defer func() { _ = sys.Shutdown() }()

	if err := sys.SetDataSources(datasrcs.GetAllSources(sys)); err != nil {
		fmt.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}

	// Setup the new enumeration
	e := enum.NewEnumeration(cfg, sys, sys.GraphDatabases()[0])
	if e == nil {
		fmt.Fprintf(color.Error, "%s\n", "Failed to setup the enumeration")
		os.Exit(1)
	}
	var wg sync.WaitGroup
	outChans := make(chan string, 50)

	// Run the enumeration process and send the results to the channel
	wg.Add(1)
	go processOutput(ctx, sys.GraphDatabases()[0], e, outChans, &wg)

	// Start the goroutine to write the results to the output file
	wg.Add(1)
	go utils.WriteFiles(ctx, &wg, outChans, WorkDirectory+"/data/output/AmassDomainOSINT.txt")

	// Start Amass enumeration
	if err := e.Start(ctx); err != nil {
		log.Fatalf("Failed to start Amass enumeration: %v", err)
	}

	wg.Wait()
}
