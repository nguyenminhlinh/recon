package domain

import (
	"context"
	"fmt"
	"os"
	"recon/utils"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const maxGoroutines = 10    // Limit the number of concurrent goroutines
const maxChanSemaphore = 10 // Limit the number of elements in the chan semaphore
const maxChanResults = 10   // Limit the number of elements in chan results

func FuffDomainHttp(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string, WorkDirectory string) {
	//Using the wrong host to get length web content "C:/Users/minhl/recon/src/data/common.txt"
	lengthResponse := utils.LengthResponse(domain, "abcdefghiklm."+domain)
	utils.Ffuf(ctx, cancel, domain, strconv.Itoa(lengthResponse), WorkDirectory+"/data/output/FuffDomainHttp.json", "domain", true, 0, wordlist)
}

func dig(domain string, qtype uint16) []dns.RR {
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
		fmt.Printf("Error: %v at domain %s \n", err, domain)
		return []dns.RR{}
	}
	return response.Answer
	// // Check DNS status code (Rcode)
	// fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n", dns.RcodeToString[response.Rcode], response.Id)
	// fmt.Printf(";; query time: %v msec\n", rtt.Milliseconds())

	// // Print the response if the status is NOERROR
	// if response.Rcode == dns.RcodeSuccess {
	// 	for _, answer := range response.Answer {
	// 		fmt.Println(answer.String())
	// 	}
	// } else {
	// 	fmt.Printf("Query failed with status: %s\n", dns.RcodeToString[response.Rcode])
	// }
}

func checkDomain(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, domain string, count *int, mu *sync.Mutex) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done(): //If a cancel signal is received from context
			mu.Lock()
			(*count)++
			if *count == maxChanSemaphore {
				for len(semaphore) > 0 {
					<-semaphore // Read and skip data until the channel is empty
				}
				close(results) //Close the results channel after stop context
			}
			mu.Unlock()
			return
		default:
			subdomain, ok := <-semaphore
			if !ok {
				(*count)++
				if *count == maxChanSemaphore {
					for len(semaphore) > 0 {
						<-semaphore // Read and skip data until the channel is empty
					}
					close(results) //Close the results channel after the goroutines complete
				}
				return
			} else {
				responseAnswer := dig(subdomain+"."+domain, dns.TypeA)
				fmt.Println(responseAnswer, subdomain)
				if len(responseAnswer) != 0 {
					fmt.Fprintf(os.Stdout, "Subdomain tồn tại:: %-35s \n", subdomain)
					results <- subdomain + "\n"
				}
			}
		}
	}
}

func BruteDomainDNS(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string, WorkDirectory string) {
	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex

	// Create semaphore channel to receive info from file and sen to checkDomain
	semaphore := make(chan string, maxChanSemaphore)
	// Create semaphore channel to receive info from checkDomain and send to writeFiles
	results := make(chan string, maxChanResults)

	// Start the goroutine to read the file into chan
	wg.Add(1)
	go utils.ReadFiles(ctx, &wg, wordlist, semaphore)

	// Start goroutines to check the domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(ctx, &wg, semaphore, results, domain, &count, &mu)
	}

	// Start the goroutine to write the results to the output file
	wg.Add(1)
	go utils.WriteFiles(ctx, &wg, results, WorkDirectory+"/data/output/BruteDomainDNS.txt")

	// Chờ tất cả các goroutines hoàn thành
	wg.Wait()
}
