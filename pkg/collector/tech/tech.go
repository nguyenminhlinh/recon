package tech

import (
	"io"
	"log"
	"net/http"

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
