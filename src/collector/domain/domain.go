package domain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"recon/utils"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/enum"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

const maxGoroutines = 10    // Limit the number of concurrent goroutines
const maxChanSemaphore = 10 // Limit the number of elements in the chan semaphore
const maxChanResults = 10   // Limit the number of elements in chan results

func DomainBruteForceHttp(domain string, wordList string, workDirectory string) {
	//Using the wrong host to get length web content "C:/Users/minhl/recon/src/data/common.txt"
	lengthResponse := utils.LengthResponse(domain, "abcdefghiklm."+domain)
	utils.Ffuf(domain, strconv.Itoa(lengthResponse), workDirectory+"/data/output/DomainBruteForceHttp.txt", "domain", true, 0, wordList)
}

func checkDomain(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, domain string, count *int, mu *sync.Mutex) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done(): //If a cancel signal is received from context
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
				responseAnswer := utils.Dig(subdomain+"."+domain, dns.TypeA)
				//fmt.Println(responseAnswer, subdomain)
				if len(responseAnswer) != 0 {
					//fmt.Fprintf(os.Stdout, "Subdomain tồn tại:: %-35s \n", subdomain)
					results <- subdomain + "." + domain
				}
			}
		}
	}
}

func DomainBruteForceDNS(ctx context.Context, cancel context.CancelFunc, domain string, wordList string, workDirectory string) {
	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex
	var countReadFiles int
	var muReadFiles sync.Mutex
	// Create semaphore channel to receive info from file and sen to checkDomain
	semaphore := make(chan string, maxChanSemaphore)
	// Create semaphore channel to receive info from checkDomain and send to writeFiles
	results := make(chan string, maxChanResults)

	// Start the goroutine to read the file into chan
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, wordList, semaphore, &countReadFiles, &muReadFiles, 1)

	// Start goroutines to check the domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(ctx, &wg, semaphore, results, domain, &count, &mu)
	}

	// Start the goroutine to write the results to the output file
	wg.Add(1)
	go utils.WriteFiles(ctx, &wg, results, workDirectory+"/data/output/DomainBruteForceDNS.txt")

	// Wait for all goroutines to complete
	wg.Wait()
}

func NewOutput(ctx context.Context, g *netmap.Graph, e *enum.Enumeration, filter *stringset.Set, since time.Time, domain string) []string {
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
		fromstr := fmt.Sprintf("%v", from.Asset)
		if strings.Contains(fromstr, domain) {
			output = append(output, fromstr[2:len(fromstr)-1])
		}
		if rels, err := g.DB.OutgoingRelations(from, start); err == nil {
			for _, rel := range rels {
				lineid := from.ID + rel.ID + rel.ToAsset.ID
				if filter.Has(lineid) {
					continue
				}
				if to, err := g.DB.FindById(rel.ToAsset.ID, start); err == nil {
					tostr := fmt.Sprintf("%v", to.Asset)
					if strings.Contains(tostr, domain) {
						// fmt.Println(fromstr, "-->", rel.Type, "-->", tostr)
						output = append(output, tostr[2:len(tostr)-1])
					}
					filter.Insert(lineid)
				}
			}
		}
	}

	return output
}

func processOutput(ctx context.Context, ctxTimeout context.Context, g *netmap.Graph, e *enum.Enumeration, outputs chan string, wg *sync.WaitGroup, domain string) {
	defer wg.Done()
	defer close(outputs)

	// This filter ensures that we only get new names
	known := stringset.New()
	defer known.Close()

	// The function that obtains output from the enum and puts it on the channel
	extract := func(since time.Time) {
		for _, output := range NewOutput(ctx, g, e, known, since, domain) {
			outputs <- output
		}
	}

	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	last := e.Config.CollectionStartTime
	for {
		select {
		case <-ctxTimeout.Done():
			extract(last)
			return
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

func DomainOSINTAmass(ctx context.Context, cancel context.CancelFunc, domain string, workDirectory string) {
	// Create configuration for Amass
	cfg := config.NewConfig()

	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(workDirectory+"/data/output", workDirectory+"/data/input/config.yaml", cfg); err != nil {
		log.Fatalf("Failed to configuration file: %v", err)
	}
	cfg.AddDomain(domain) // Add domains to check

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		log.Fatalf("Failed to create system: %v", err)
	}
	defer func() { _ = sys.Shutdown() }()

	if err := sys.SetDataSources(datasrcs.GetAllSources(sys)); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Set the timeout by configuring the time for the context
	timeout := 20 * time.Minute
	ctxTimeout, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	// Setup the new enumeration
	e := enum.NewEnumeration(cfg, sys, sys.GraphDatabases()[0])
	if e == nil {
		fmt.Println("Failed to setup the enumeration")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	outChans := make(chan string, 50)

	// Run the enumeration process and send the results to the channel
	wg.Add(1)
	go processOutput(ctx, ctxTimeout, sys.GraphDatabases()[0], e, outChans, &wg, domain)

	// Start the goroutine to write the results to the output file
	wg.Add(1)
	go utils.WriteFiles(ctx, &wg, outChans, workDirectory+"/data/output/DomainOSINTAmass.txt")

	// Monitor for cancellation by the user
	go func(c context.Context, f context.CancelFunc) {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(quit)
		select {
		case <-quit:
			f()
		case <-c.Done():
		}
	}(ctx, cancel)

	// Start the enumeration process
	if err := e.Start(ctxTimeout); err != nil {
		log.Fatalf("Failed to start Amass enumeration: %v", err)
	}
}

func DomainOSINTSubfinder(ctx context.Context, cancel context.CancelFunc, domain string, WorkDirectory string) {
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Silent:             true,
		// ResultCallback: func(s *resolve.HostEntry) {
		// callback function executed after each unique subdomain is found
		// },
		ProviderConfig: WorkDirectory + "/data/input/provider-config.yaml",
		// and other config related options
	}

	// disable timestamps in logs / configure logger
	log.SetFlags(0)

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Fatalf("failed to create subfinder runner: %v", err)
	}

	output := &bytes.Buffer{}
	// To run subdomain enumeration on a single domain
	if err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate single domain: %v", err)
	}

	var wg sync.WaitGroup
	outChans := make(chan string, 50)
	outChans <- output.String()
	close(outChans)

	// Start the goroutine to write the results to the output file
	wg.Add(1)
	go utils.WriteFiles(ctx, &wg, outChans, WorkDirectory+"/data/output/DomainOSINTSubfinder.txt")

	// Monitor for cancellation by the user
	go func(c context.Context, f context.CancelFunc) {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(quit)
		select {
		case <-quit:
			f()
		case <-c.Done():
		}
	}(ctx, cancel)

	wg.Wait()
}
