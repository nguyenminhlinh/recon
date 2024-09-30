package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"recon/pkg/collector/port"
	data "recon/pkg/data/type"
	"strconv"
	"strings"
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
	dnsServer := "8.8.4.4:53" //Use Google DNS

	// Create a client to send DNS requests
	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	// Send DNS requests
	response, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		return []dns.RR{}
	}
	return response.Answer
}

func GetIpAndcName(ctx context.Context, wgDomain *sync.WaitGroup, subDomain string, infoSubDomain *data.InfoSubDomain, cloudflareIPs *[]string, incapsulaIPs *[]string, awsCloudFrontIPs *[]string, gcoreIPs *[]string, fastlyIPs *[]string, workDirectory string) {
	defer wgDomain.Done()

	infoDigs := Dig(subDomain, dns.TypeA)
	flagScanPort := false

	if len(infoDigs) != 0 {
		for _, infoDig := range infoDigs {
			if aRecord, ok := infoDig.(*dns.A); ok {
				ip := aRecord.A.String()
				checkIntermediaryIp, nameOrganisation := CheckIntermediaryIp(ip, cloudflareIPs, incapsulaIPs, awsCloudFrontIPs, gcoreIPs, fastlyIPs)
				if checkIntermediaryIp {
					infoSubDomain.Ips = append(infoSubDomain.Ips, ip+" : "+nameOrganisation)
				} else {
					infoSubDomain.Ips = append(infoSubDomain.Ips, ip)
					flagScanPort = true //If domain have ip is not intermediary ip
				}
			} else if cNameRecord, ok := infoDig.(*dns.CNAME); ok {
				infoSubDomain.CName = append(infoSubDomain.CName, cNameRecord.Target)
			}
		}
	}

	if flagScanPort {
		port.ScanPortAndService(subDomain, infoSubDomain, workDirectory)
	}
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
		infoDomain.TXTRecords = []string{}
	} else {
		infoDomain.TXTRecords = txtRecords
	}
}

type CloudflareIPs struct {
	Addresses []string `json:"addresses"`
}

type IncapsulaIPs struct {
	IpRanges []string `json:"ipRanges"`
}

type AWSCloudFrontIPs struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
		Service  string `json:"service"`
	} `json:"prefixes"`
}

type GcoreIPs struct {
	Addresses []string `json:"addresses"`
}

type FastlyIPs struct {
	Addresses []string `json:"addresses"`
}

func getCloudflareIPs() ([]string, error) {
	resp, err := http.Get("https://www.cloudflare.com/ips-v4")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	cloudFlare := strings.Split(string(body), "\n")

	return cloudFlare, nil
}

func getIncapsulaIPs() ([]string, error) {
	resp, err := http.Get("https://my.imperva.com/api/integration/v1/ips")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var incapsula IncapsulaIPs
	if err := json.NewDecoder(resp.Body).Decode(&incapsula); err != nil {
		return nil, err
	}

	return incapsula.IpRanges, nil
}

func getAWSCloudFrontIPs() ([]string, error) {
	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var AWSCloudFront AWSCloudFrontIPs
	if err := json.NewDecoder(resp.Body).Decode(&AWSCloudFront); err != nil {
		return nil, err
	}

	var ipPrefixes []string
	for _, prefix := range AWSCloudFront.Prefixes {
		if strings.Contains(strings.ToLower(prefix.Service), "cloudfront") {
			ipPrefixes = append(ipPrefixes, prefix.IPPrefix)
		}
	}

	return ipPrefixes, nil
}

func getGcoreIPs() ([]string, error) {
	resp, err := http.Get("https://api.gcore.com/cdn/public-ip-list")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var gcore GcoreIPs
	if err := json.NewDecoder(resp.Body).Decode(&gcore); err != nil {
		return nil, err
	}

	return gcore.Addresses, nil
}

func getFastlyIPs() ([]string, error) {
	resp, err := http.Get("https://api.fastly.com/public-ip-list")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var fastly FastlyIPs
	if err := json.NewDecoder(resp.Body).Decode(&fastly); err != nil {
		return nil, err
	}

	return fastly.Addresses, nil
}

func isIPInRange(ip string, ranges []string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		fmt.Printf("Invalid IP address: %s\n", ip)
		return false
	}

	for _, r := range ranges {
		_, netRange, err := net.ParseCIDR(r)
		if err != nil {
			fmt.Printf("Error parsing CIDR: %s\n", r)
			continue // Bỏ qua dải IP không hợp lệ
		}
		if netRange.Contains(ipAddr) {
			return true
		}
	}

	return false
}

func GetIntermediaryIpRange() ([]string, []string, []string, []string, []string) {
	cloudflareIPs, err := getCloudflareIPs()
	if err != nil {
		fmt.Println("Error getting Cloudflare IPs:", err)
	}

	incapsulaIPs, err := getIncapsulaIPs()
	if err != nil {
		fmt.Println("Error getting Cloudflare IPs:", err)
	}

	awsCloudFrontIPs, err := getAWSCloudFrontIPs()
	if err != nil {
		fmt.Println("Error getting AWSCloudFront IPs:", err)
	}

	gcoreIPs, err := getGcoreIPs()
	if err != nil {
		fmt.Println("Error getting AWSCloudFront IPs:", err)
	}

	fastlyIPs, err := getFastlyIPs()
	if err != nil {
		fmt.Println("Error getting Fastly IPs:", err)
	}

	return cloudflareIPs, incapsulaIPs, awsCloudFrontIPs, gcoreIPs, fastlyIPs
}

func CheckIntermediaryIp(ipToCheck string, cloudflareIPs *[]string, incapsulaIPs *[]string, awsCloudFrontIPs *[]string, gcoreIPs *[]string, fastlyIPs *[]string) (bool, string) {
	if isIPInRange(ipToCheck, *cloudflareIPs) {
		return true, "cloudflareIPs"
	} else if isIPInRange(ipToCheck, *incapsulaIPs) {
		return true, "IncapsulaIPs"
	} else if isIPInRange(ipToCheck, *awsCloudFrontIPs) {
		return true, "awsCloudFrontIPs"
	} else if isIPInRange(ipToCheck, *gcoreIPs) {
		return true, "GcoreIPs"
	} else if isIPInRange(ipToCheck, *fastlyIPs) {
		return true, "fastlyIPs"
	} else {
		return false, ""
	}
}
