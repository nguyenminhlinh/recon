package vuln

import (
	"context"
	"fmt"
	data "recon/pkg/data/type"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func ScanVulnerability(listScanVuln map[string]bool, ctx context.Context, subDomainChan chan string, infoAllVulnerability map[string][]data.InfoVulnerability, typeScan int) {
	var timeOut time.Duration
	var mu sync.Mutex
	if typeScan == 1 {
		timeOut = 10 * time.Minute // Set the timeout by configuring the time for the context
	} else if typeScan == 2 {
		timeOut = 20 * time.Minute // Set the timeout by configuring the time for the context
	} else if typeScan == 3 {
		timeOut = 30 * time.Minute // Set the timeout by configuring the time for the context
	}

	// create nuclei engine with options
	// setup sizedWaitgroup to handle concurrency
	// here we are using sizedWaitgroup to limit concurrency to 1
	// but can be anything in general
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx)
	if err != nil {
		fmt.Println("NewThreadSafeNucleiEngineCtx", err)
		return
	}

	ne.GlobalLoadAllTemplates()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for subDomain := range subDomainChan {
				ctxTimeout, cancelTimeout := context.WithTimeout(ctx, timeOut)
				defer cancelTimeout()
				err = ne.ExecuteNucleiWithOptsCtx(ctxTimeout, []string{subDomain},
					nuclei.WithTemplateFilters(nuclei.TemplateFilters{}),
				)
				if err != nil {
					fmt.Println("ExecuteNucleiWithOptsCtx", err)
					return
				}
				listScanVuln[subDomain] = true
			}
			defer wg.Done()
		}()
	}

	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		var infoVulnerability data.InfoVulnerability
		infoVulnerability.NameSubDomain = event.Host
		infoVulnerability.TemplateID = event.TemplateID
		infoVulnerability.ExtractorName = event.ExtractorName
		infoVulnerability.Matched = event.Matched
		infoVulnerability.MatcherName = event.MatcherName
		infoVulnerability.Type = event.Type
		infoVulnerability.TemplateName = event.Info.Name
		infoVulnerability.Classification = fmt.Sprintf("%v", event.Info.Classification)

		if len(event.Info.Description) > 0 {
			infoVulnerability.TemplateDescription = event.Info.Description
		}

		if len(event.Info.SeverityHolder.Severity.String()) > 0 {
			infoVulnerability.Severity = event.Info.SeverityHolder.Severity.String()
		}

		if len(event.ExtractedResults) > 0 {
			infoVulnerability.ExtractedResults = event.ExtractedResults
		}

		mu.Lock() // Lock map before accessing it
		infoVulnerabilitySlice := infoAllVulnerability[event.Host]
		infoVulnerabilitySlice = append(infoVulnerabilitySlice, infoVulnerability)
		infoAllVulnerability[event.Host] = infoVulnerabilitySlice
		mu.Unlock()
	})

	//wait for all scans to finish
	wg.Wait()
	defer ne.Close()

}
