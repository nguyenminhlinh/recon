package data

import wappalyzer "github.com/projectdiscovery/wappalyzergo"

type InfoVulnerability struct {
	NameSubDomain       string   `json:"namesubdomain"`
	Type                string   `json:"type"`
	TemplateID          string   `json:"templateid"`
	Severity            string   `json:"severity"`
	ExtractorName       string   `json:"extractorname"`
	MatcherName         string   `json:"matchername"`
	Matched             string   `json:"matched"`
	TemplateName        string   `json:"templatename"`
	TemplateDescription string   `json:"templatedescription"`
	ExtractedResults    []string `json:"extractedresults"`
	Classification      string   `json:"classification"`
}

type InfoWeb struct {
	TechnologyDetails map[string]wappalyzer.AppInfo `json:"technologydetails"`
	Link              []string                      `json:"link"`
	Status            string                        `json:"status"`
	Title             string                        `json:"title"`
}

type InfoSubDomain struct {
	NameSubDomain     string             `json:"namesubdomain"`
	Ips               []string           `json:"ips"`
	PortAndService    map[string]string  `json:"portsandservice"`
	Os                []string           `json:"os"`
	Web               map[string]InfoWeb `json:"web"`
	CName             []string           `json:"cname"`
	FlagVulnerability bool               `json:"flagvulnerability"`
}

type InfoDomain struct {
	MXRecords     []string                       `json:"mxrecords"`
	NSRecords     []string                       `json:"nsrecords"`
	SOARecords    []string                       `json:"soarecords"`
	TXTRecords    []string                       `json:"txtrecords"`
	Vulnerability map[string][]InfoVulnerability `json:"vulnerability"`
	SubDomain     map[string]InfoSubDomain       `json:"subdomain"`
}

var ListDomain = make(map[string]InfoDomain)
