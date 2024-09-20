package dns

import (
	data "recon/data/type"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func Dig(domain string, qtype uint16) []dns.RR {
	// Create a DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	// Select the DNS server to query
	dnsServer := "8.8.8.8:53" //Use Google DNS

	// Create a client to send DNS requests
	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	// Send DNS requests
	response, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		//	fmt.Printf("Error: %v at domain %s \n", err, domain)
		return []dns.RR{}
	}
	return response.Answer
}

func GetIpAndcName(wgDomain *sync.WaitGroup, domain string, infoDomain *data.InfoDomain) {
	domainHaveIPs := Dig(domain, dns.TypeA)
	if len(domainHaveIPs) != 0 {
		infoDomain.DomainName = domain
		for _, DomainHaveIP := range domainHaveIPs {
			if aRecord, ok := DomainHaveIP.(*dns.A); ok {
				infoDomain.Ips = append(infoDomain.Ips, aRecord.A.String())
			} else if cNameRecord, ok := DomainHaveIP.(*dns.CNAME); ok {
				infoDomain.CName = append(infoDomain.CName, cNameRecord.Target)
			}
		}
	} else {
		infoDomain.DomainName = domain
	}
	wgDomain.Done()
}
