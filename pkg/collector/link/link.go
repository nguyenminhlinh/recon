package link

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func GetURL(ctx context.Context, subDomain string, typeScan int) []string {
	noSubs := true
	fetchFns := []fetchFn{
		getWaybackURLs,
		getCommonCrawlURLs,
		getVirusTotalURLs,
	}

	var wg sync.WaitGroup
	wurls := make(chan wurl, 100)

	for _, fn := range fetchFns {
		wg.Add(1)
		fetch := fn
		go func(typeScan int) {
			defer wg.Done()
			resp, err := fetch(subDomain, noSubs, typeScan)
			if err != nil {
				return
			}
			for _, r := range resp {
				if noSubs && isSubdomain(r.url, subDomain) {
					continue
				}
				wurls <- r
			}
		}(typeScan)
	}

	go func() {
		wg.Wait()
		close(wurls)
	}()

	seen := make(map[string]bool)
	var link []string
	for w := range wurls {
		if _, ok := seen[w.url]; ok {
			continue
		}
		seen[w.url] = true
		link = append(link, w.url)
	}

	return link
}

type wurl struct {
	date string
	url  string
}

type fetchFn func(string, bool, int) ([]wurl, error)

func getWaybackURLs(domain string, noSubs bool, typeScan int) ([]wurl, error) {
	var timeOut time.Duration
	if typeScan == 1 {
		timeOut = 10 * time.Minute
	} else if typeScan == 2 {
		timeOut = 20 * time.Minute
	} else if typeScan == 3 {
		timeOut = 30 * time.Minute
	}
	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), timeOut)
	defer cancelTimeout()

	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	// Create request with context so it can be canceled upon timeout
	req, err := http.NewRequestWithContext(ctxTimeout, "GET",
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain),
		nil)
	if err != nil {
		return []wurl{}, err
	}

	// Make request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return []wurl{}, err
	}
	defer res.Body.Close()

	// Read data directly from res.Body
	raw, err := io.ReadAll(res.Body)

	if err != nil {
		return []wurl{}, err
	}

	var wrapper [][]string
	_ = json.Unmarshal(raw, &wrapper)

	out := make([]wurl, 0, len(wrapper))

	skip := true
	for _, urls := range wrapper {
		// The first item is always just the string "original",
		// so we should skip the first item
		if skip {
			skip = false
			continue
		}
		out = append(out, wurl{date: urls[1], url: urls[2]})
	}

	return out, nil
}

func getCommonCrawlURLs(domain string, noSubs bool, typeScan int) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain),
	)
	if err != nil {
		return []wurl{}, err
	}

	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	out := make([]wurl, 0)

	for sc.Scan() {

		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)

		if err != nil {
			continue
		}
		out = append(out, wurl{date: wrapper.Timestamp, url: wrapper.URL})
	}

	return out, nil
}

func getVirusTotalURLs(domain string, noSubs bool, typeScan int) ([]wurl, error) {
	out := make([]wurl, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		// no API key isn't an error,
		// just don't fetch
		return out, nil
	}

	fetchURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey,
		domain,
	)

	resp, err := http.Get(fetchURL)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
			// TODO: handle VT date format (2018-03-26 09:22:43)
			//Date string `json:"scan_date"`
		} `json:"detected_urls"`
	}{}

	dec := json.NewDecoder(resp.Body)

	_ = dec.Decode(&wrapper)

	for _, u := range wrapper.URLs {
		out = append(out, wurl{url: u.URL})
	}

	return out, nil
}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		// we can't parse the URL so just
		// err on the side of including it in output
		return false
	}
	return !strings.EqualFold(u.Hostname(), domain)
}
