package data

import wappalyzer "github.com/projectdiscovery/wappalyzergo"

type InfoWeb struct {
	TechnologyDetails map[string]wappalyzer.AppInfo `json:"technologydetails"`
	Link              []string                      `json:"link"`
	DirAndFile        []string                      `json:"dirandfile"`
	FireWall          string                        `json:"firewall"`
	Status            string                        `json:"ttatus"`
	Title             string                        `json:"title"`
}

type InfoSubDomain struct {
	Ips            []string           `json:"ips"`
	PortAndService map[string]string  `json:"portandservice"`
	HttpOrHttps    map[string]InfoWeb `json:"httporhttps"`
	CName          []string           `json:"cname"`
}

type InfoDomain struct {
	MXRecords  []string                 `json:"mxrecords"`
	NSRecords  []string                 `json:"nsrecords"`
	SOARecords []string                 `json:"soarecords"`
	TXTRecords []string                 `json:"txtrecords"`
	SubDomain  map[string]InfoSubDomain `json:"subdomain"`
}

var ListDomain = make(map[string]InfoDomain)
