package tech

import (
	"context"
	"io"
	"log"
	"net/http"
	"recon/pkg/collector/link"
	data "recon/pkg/data/type"
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

func HttpAndHttps(domain string) (string, string, string, map[string]wappalyzer.AppInfo, bool) {
	// Check HTTPS
	url := "https://" + domain
	Resp, err := http.Get(url)
	if err == nil {
		status := Resp.Status
		title := extractTitle(Resp)
		tech := Tech(url)
		Resp.Body.Close()
		return url, status, title, tech, true
	}

	// Check HTTP
	url = "http://" + domain
	Resp, err = http.Get(url)
	if err == nil {
		status := Resp.Status
		title := extractTitle(Resp)
		tech := Tech(url)
		Resp.Body.Close()
		return url, status, title, tech, true
	}

	return "", "", "", map[string]wappalyzer.AppInfo{}, false
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

func HttpxSimple(ctx context.Context, wgSubDomain *sync.WaitGroup, subDomain string, infoSubDomain *data.InfoSubDomain, typeScan int) {
	defer wgSubDomain.Done()

	url, status, title, tech, flagGetURL := HttpAndHttps(subDomain)
	var allLink []string
	if flagGetURL { //Only getURL if subdomain have type http or https
		allLink = link.GetURL(ctx, subDomain, typeScan)
	}

	if infoSubDomain.HttpOrHttps == nil {
		infoSubDomain.HttpOrHttps = make(map[string]data.InfoWeb)
	}

	infoWeb := infoSubDomain.HttpOrHttps[url]
	infoWeb.Link = allLink
	infoWeb.Status = status
	infoWeb.Title = title

	if infoWeb.TechnologyDetails == nil {
		infoWeb.TechnologyDetails = make(map[string]wappalyzer.AppInfo)
	}

	for key, value := range tech {
		infoWeb.TechnologyDetails[key] = value
	}

	infoSubDomain.HttpOrHttps[url] = infoWeb
}
