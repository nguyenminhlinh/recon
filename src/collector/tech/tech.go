package tech

import (
	"io"
	"log"
	"net/http"
	data "recon/data/type"
	"sync"

	"github.com/PuerkitoBio/goquery"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func Tech(url string) map[string]wappalyzer.AppInfo {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("Error getting technology info:", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading response body:", err)
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatal("Error creating Wappalyzer client:", err)
	}

	// Collect fingerprints with info
	fingerprintsWithInfo := wappalyzerClient.FingerprintWithInfo(resp.Header, data)
	return fingerprintsWithInfo
}

func HttpAndHttps(domain string) (string, string, string, map[string]wappalyzer.AppInfo) {
	// Check HTTPS
	url := "https://" + domain
	Resp, err := http.Get(url)
	if err == nil {
		status := Resp.Status
		title := extractTitle(Resp)
		tech := Tech(url)
		Resp.Body.Close()
		return url, status, title, tech
	}

	// Check HTTP
	url = "http://" + domain
	Resp, err = http.Get(url)
	if err == nil {
		status := Resp.Status
		title := extractTitle(Resp)
		tech := Tech(url)
		Resp.Body.Close()
		return url, status, title, tech
	}

	return "", "", "", map[string]wappalyzer.AppInfo{}
}

// extractTitle gets the title from the response
func extractTitle(resp *http.Response) string {
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "Error parsing document"
	}

	// Get the title from the <title> tag
	title := doc.Find("title").Text()
	return title
}

func HttpxSimple(wgSubDomain *sync.WaitGroup, subDomain string, infoSubDomain *data.InfoSubDomain) {
	url, status, title, tech := HttpAndHttps(subDomain)

	if infoSubDomain.HttpOrHttps == nil {
		infoSubDomain.HttpOrHttps = make(map[string]data.InfoWeb)
	}

	infoWeb := infoSubDomain.HttpOrHttps[url]
	infoWeb.Status = status
	infoWeb.Title = title
	if infoWeb.TechnologyDetails == nil {
		infoWeb.TechnologyDetails = make(map[string]wappalyzer.AppInfo)
	}

	for key, value := range tech {
		infoWeb.TechnologyDetails[key] = value
	}

	infoSubDomain.HttpOrHttps[url] = infoWeb

	wgSubDomain.Done()
}

// func HttpxSimple(wgDomain *sync.WaitGroup, domain string, InfoDomain *data.InfoDomain) {
// 	options := runnerhttpx.Options{
// 		Methods:         "GET",
// 		InputTargetHost: goflags.StringSlice{domain},
// 		TechDetect:      true,
// 		Threads:         1,
// 		Silent:          true,
// 		OnResult: func(r runnerhttpx.Result) {
// 			// handle error
// 			if r.Err != nil {
// 				fmt.Printf("[Err] %s: %s\n", r.Input, r.Err)
// 				return
// 			}

// 			if InfoDomain.HttpOrHttps == nil {
// 				InfoDomain.HttpOrHttps = make(map[string]data.InfoWeb)
// 			}

// 			infoWeb := InfoDomain.HttpOrHttps[r.URL]
// 			if infoWeb.TechnologyDetails == nil {
// 				infoWeb.TechnologyDetails = make(map[string]wappalyzer.AppInfo)
// 			}

// 			for key, value := range r.TechnologyDetails {
// 				infoWeb.TechnologyDetails[key] = value
// 			}

// 			infoWeb.Status = strconv.Itoa(r.StatusCode)
// 			infoWeb.Title = r.Title

// 			InfoDomain.HttpOrHttps[r.URL] = infoWeb
// 			//fmt.Printf("%s %s %d %v\n", r.Input, r.Host, r.StatusCode, r.Technologies)
// 		},
// 	}

// 	if err := options.ValidateOptions(); err != nil {
// 		log.Fatal(err)
// 	}

// 	httpxRunner, err := runnerhttpx.New(&options)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	defer httpxRunner.Close()
// 	httpxRunner.RunEnumeration()
// 	wgDomain.Done()
// }
