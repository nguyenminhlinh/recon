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

type InfoDomain struct {
	DomainName     string             `json:"domainname"`
	Ips            []string           `json:"ips"`
	PortAndService map[string]string  `json:"portandservice"`
	HttpOrHttps    map[string]InfoWeb `json:"httporhttps"`
	CName          []string           `json:"cname"`
}

var ListDomain = make(map[string]InfoDomain)
