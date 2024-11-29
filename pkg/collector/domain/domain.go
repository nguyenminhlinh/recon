package domain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"

	"strings"
	"sync"
	"syscall"
	"time"

	dnsrecon "recon/pkg/collector/dns"
	"recon/pkg/utils"
	output "recon/pkg/utils/output_ffuf"

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

func checkDomain(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, domain string, count *int, mu *sync.Mutex, maxGoroutines int) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done(): //If a cancel signal is received from context
			mu.Lock()
			(*count) += 1
			if *count == maxGoroutines {
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
				mu.Lock()
				(*count) += 1
				if *count == maxGoroutines {
					for len(semaphore) > 0 {
						<-semaphore // Read and skip data until the channel is empty
					}
					results <- domain
					close(results) //Close the results channel after the goroutines complete
				}
				mu.Unlock()
				return
			} else {
				if domain != "" { //DomainBruteForceDNS with subdomain don't have domain
					responseAnswer := dnsrecon.Dig(subdomain+"."+domain, dns.TypeA, "8.8.4.4")
					if len(responseAnswer) != 0 {
						results <- subdomain + "." + domain
					}
				} else { //DomainOSINTSubfinder with subdomain had domain
					responseAnswer := dnsrecon.Dig(subdomain, dns.TypeA, "8.8.4.4")
					if len(responseAnswer) != 0 {
						results <- subdomain
					}
				}
			}
		}
	}
}

func DomainBruteForceDNS(ctx context.Context, cancel context.CancelFunc, domain string, wordList string, results chan string) {
	var wg sync.WaitGroup
	var count = 0
	var mu sync.Mutex

	var countReadFiles int
	var muReadFiles sync.Mutex

	const maxGoroutines = 100   // Limit the number of concurrent goroutines
	const maxChanSemaphore = 50 // Limit the number of elements in the chan semaphore
	// Create semaphore channel to receive info from file and sen to checkDomain
	semaphore := make(chan string, maxChanSemaphore)

	// Start the goroutine to read the file into chan
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, wordList, semaphore, &countReadFiles, &muReadFiles, 1)

	// Start goroutines to check the domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(ctx, &wg, semaphore, results, domain, &count, &mu, maxGoroutines)
	}

	// Wait for all goroutines to complete
	wg.Wait()
}

func DomainOSINTSubfinder(ctx context.Context, cancel context.CancelFunc, domain string, workDirectory string, chanResults chan string) {
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

	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Silent:             true,
		// ResultCallback: func(s *resolve.HostEntry) {
		// callback function executed after each unique subdomain is found
		// },
		ProviderConfig: workDirectory + "/pkg/data/input/DomainOSINTSubfinder-Config.yaml",
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
	if err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate single domain: %v", err)
	}

	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex
	inputChans := make(chan string, 50)
	const maxGoroutines = 10 // Limit the number of concurrent goroutines

	// Split string into slices based on line breaks
	domains := strings.Split(output.String(), "\n")
	go func() {
		for _, domainLine := range domains {
			inputChans <- domainLine
		}
		close(inputChans)
	}()

	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(ctx, &wg, inputChans, chanResults, "", &count, &mu, maxGoroutines)
	}
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
						output = append(output, tostr[2:len(tostr)-1])
					}
					filter.Insert(lineid)
				}
			}
		}
	}

	return output
}

func processOutput(ctx context.Context, ctxTimeout *context.Context, g *netmap.Graph, e *enum.Enumeration, outputs chan string, wg *sync.WaitGroup, domain string) {
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
		case <-(*ctxTimeout).Done():
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

func DomainOSINTAmass(ctx context.Context, cancel context.CancelFunc, domain string, workDirectory string, chanResults chan string, typeScan int) {
	cfg := config.NewConfig()

	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(workDirectory+"/pkg/data/output", workDirectory+"/pkg/data/input/DomainOSINTAmass.yaml", cfg); err != nil {
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

	var timeOut time.Duration
	if typeScan == 1 {
		timeOut = 10 * time.Minute // Set the timeout by configuring the time for the context
	} else if typeScan == 2 {
		timeOut = 20 * time.Minute // Set the timeout by configuring the time for the context
	} else if typeScan == 3 {
		timeOut = 30 * time.Minute // Set the timeout by configuring the time for the context
	}
	ctxTimeout, cancelTimeout := context.WithTimeout(ctx, timeOut)
	defer cancelTimeout()

	// Setup the new enumeration
	e := enum.NewEnumeration(cfg, sys, sys.GraphDatabases()[0])
	if e == nil {
		fmt.Println("Failed to setup the enumeration")
		os.Exit(1)
	}

	var wg sync.WaitGroup

	// Run the enumeration process and send the results to the channel
	wg.Add(1)
	go processOutput(ctx, &ctxTimeout, sys.GraphDatabases()[0], e, chanResults, &wg, domain)

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

func DomainBruteForceHttp(domain string, wordList string, typeScan int, results chan string) {
	var url string

	lengthResponse, flaghttp := utils.LengthResponse(domain, "abcdefghiklm."+domain)

	if flaghttp {
		url = "http://" + domain
	} else {
		url = "https://" + domain
	}

	utils.Ffuf(url, domain, strconv.Itoa(lengthResponse), "DomainBruteForceHttp", "domain", true, 0, wordList)
	for _, output := range output.OutputDomain {
		results <- output
	}
	close(results)
}
