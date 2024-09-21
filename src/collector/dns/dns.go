package dns

import (
	"fmt"
	"net"
	data "recon/data/type"
	"strconv"
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

func GetIpAndcName(wgDomain *sync.WaitGroup, subDomain string, infoSubDomain *data.InfoSubDomain) {
	infoDigs := Dig(subDomain, dns.TypeA)
	if len(infoDigs) != 0 {
		for _, infoDig := range infoDigs {
			if aRecord, ok := infoDig.(*dns.A); ok {
				infoSubDomain.Ips = append(infoSubDomain.Ips, aRecord.A.String())
			} else if cNameRecord, ok := infoDig.(*dns.CNAME); ok {
				infoSubDomain.CName = append(infoSubDomain.CName, cNameRecord.Target)
			}
		}
	}
	wgDomain.Done()
}

func DNS(RootDomain string, infoDomain *data.InfoDomain) {

	infoDigsMX := Dig(RootDomain, dns.TypeMX)
	infoDigsNS := Dig(RootDomain, dns.TypeNS)
	infoDigsSOA := Dig(RootDomain, dns.TypeSOA)

	if len(infoDigsMX) != 0 {
		for _, infoDigMX := range infoDigsMX {
			mx := infoDigMX.(*dns.MX).Mx
			preference := infoDigMX.(*dns.MX).Preference
			infoDomain.MXRecords = append(infoDomain.MXRecords, strconv.FormatUint(uint64(preference), 10)+" "+mx)
		}
	}

	if len(infoDigsNS) != 0 {
		for _, infoDigNS := range infoDigsNS {
			NSRecord := infoDigNS.(*dns.NS).Ns
			infoDomain.NSRecords = append(infoDomain.NSRecords, NSRecord)
		}
	}

	if len(infoDigsSOA) != 0 {
		for _, infoDigSOA := range infoDigsSOA {
			ttl := infoDigSOA.(*dns.SOA).Refresh
			email := infoDigSOA.(*dns.SOA).Mbox
			infoDomain.SOARecords = append(infoDomain.SOARecords, "ttl: "+strconv.FormatUint(uint64(ttl), 10)+"  email: "+email)
		}
	}

	txtRecords, err := net.LookupTXT(RootDomain)
	if err != nil {
		fmt.Printf("Error looking up TXT records for %s: %v\n", RootDomain, err)
	} else {
		infoDomain.TXTRecords = txtRecords
	}
}
