package domain

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"recon/utils"
	"strconv"
	"sync"
)

const maxGoroutines = 10    // Limit the number of concurrent goroutines
const maxChanSemaphore = 10 // Limit the number of elements in the chan semaphore
const maxChanResults = 10   // Limit the number of elements in chan results

func FuffDomainHttp(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string) {
	//Using the wrong host to get length web content "C:/Users/minhl/recon/src/data/common.txt"
	lengthResponse := utils.LengthResponse(domain, "abcdefghiklm."+domain)
	utils.Ffuf(ctx, cancel, domain, strconv.Itoa(lengthResponse), "C:/Users/minhl/recon/src/data/output/output_domain.json", "domain", true, 0, wordlist)
}

func checkDomain(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, ips_real string, domain string, count *int, mu *sync.Mutex) {
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
				ips, err := net.LookupHost(subdomain + "." + domain)
				if err == nil {
					fmt.Println(ips)
					if ips[0][0:6] == ips_real {
						fmt.Fprintf(os.Stdout, "Subdomain tồn tại:: %-35s : %-16s : %s\n", subdomain, err, ips)
						results <- subdomain + "\n"
					}
				}
			}
		}

	}
}

func readFiles(ctx context.Context, wg *sync.WaitGroup, wordlist string, semaphore chan<- string) {
	defer wg.Done()
	defer close(semaphore)
	inputFile, err := os.Open(wordlist)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)

	for {
		select {
		case <-ctx.Done():
			return //Context cancelled, stopping file read.
		default:
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					fmt.Println("Error reading file:", err)
				}
				return //Read file finish
			}
			domain := scanner.Text()
			semaphore <- domain
		}
	}
}

func writeFiles(ctx context.Context, wg *sync.WaitGroup, results <-chan string, ouputFile string) {
	defer wg.Done()
	file, err := os.OpenFile(ouputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening output file:", err)
		return
	}
	defer file.Close()

	for {
		select {
		case result, ok := <-results:
			if !ok {
				return
			}
			_, err := file.Write([]byte(result))
			fmt.Println("write", result)
			if err != nil {
				fmt.Println("Error writing to file:", err)
			}
		case <-ctx.Done():
			return //Context cancelled, stopping file write.
		}
	}
}

func BruteDomainDNS(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string) {
	ips_reals, _ := net.LookupHost(domain)
	ips_real := ips_reals[0][0:6]
	fmt.Println(ips_reals)
	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex

	// Tạo semaphore và channel để nhận kết quả
	semaphore := make(chan string, maxChanSemaphore)
	results := make(chan string, maxChanResults)

	// Khởi động goroutine để đọc file vào chan
	wg.Add(1)
	go readFiles(ctx, &wg, wordlist, semaphore)

	// Khởi động các goroutines để kiểm tra domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(ctx, &wg, semaphore, results, ips_real, domain, &count, &mu)
	}

	// Khởi động goroutine để ghi kết quả vào file output
	wg.Add(1)
	go writeFiles(ctx, &wg, results, "C:/Users/minhl/recon/src/data/output/output_domaindns.txt")

	// Chờ tất cả các goroutines hoàn thành
	wg.Wait()
}
