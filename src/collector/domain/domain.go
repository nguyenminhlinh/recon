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

const maxGoroutines = 10    // Giới hạn số lượng goroutine đồng thời
const maxChanSemaphore = 10 // Giới hạn số lượng phần tử trong chan semaphore
const maxChanResults = 10   // Giới hạn số lượng phần tử trong chan results

func FuffDomainHttp(domain string, wordlist string) {
	//Using the wrong host to get web content "C:/Users/minhl/recon/src/data/common.txt"
	lengthResponse := utils.LengthResponse(domain, "abcdefghiklm."+domain)
	utils.Ffuf(domain, strconv.Itoa(lengthResponse), "C:/Users/minhl/recon/src/data/output/output_domain.json", "domain", true, 0, wordlist)
}

// Hàm kiểm tra domain
func checkDomain(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, ips_real string, domain string, count *int) {
	for {
		select {
		case <-ctx.Done(): // Nếu nhận được tín hiệu hủy từ context
			// Đóng channel results sau khi các goroutine hoàn thành
			wg.Done()
			return
		default:
			subdomain, ok := <-semaphore
			if !ok {
				// Đóng channel results sau khi các goroutine hoàn thành
				fmt.Println("hết dầu ra ")
				*count++
				if *count == maxChanSemaphore {
					fmt.Println("close end")
					fmt.Println(len(results))
					close(results)
				}
				wg.Done()
				return
			}
			ips, err := net.LookupHost(subdomain + "." + domain)
			if err == nil {
				if ips[0][0:6] == ips_real {
					fmt.Fprintf(os.Stdout, "Subdomain tồn tại:: %-35s : %-16s : %s\n", subdomain, err, ips)
					results <- subdomain + "\n"
				} else {
					fmt.Println("sub", subdomain)
				}
			} else {
				fmt.Println("sub", subdomain)
			}
		}
	}
}

// Hàm đọc domain từ file
// func readFiles(wordlist string, semaphore chan<- string) {
// 	// defer wg.Done()
// 	file, err := os.Open(wordlist)
// 	if err != nil {
// 		fmt.Println("Error opening file:", err)
// 		close(semaphore)
// 		return
// 	}
// 	defer file.Close()

// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		domain := scanner.Text()
// 		semaphore <- domain // Gửi domain vào channel semaphore để kiểm tra
// 	}
// 	close(semaphore)
// }

func readFiles(ctx context.Context, wg *sync.WaitGroup, wordlist string, semaphore chan<- string) {

	inputFile, err := os.Open(wordlist)
	if err != nil {
		fmt.Println("Error opening file:", err)
		close(semaphore)
		inputFile.Close()
		wg.Done()
		return
	}

	scanner := bufio.NewScanner(inputFile)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Context cancelled, stopping file read.")
			close(semaphore)
			inputFile.Close()
			wg.Done()
			return
		default:
			if scanner.Scan() {
				domain := scanner.Text()
				semaphore <- domain
				fmt.Println(domain)
			} else {
				if err := scanner.Err(); err != nil {
					fmt.Println("Error reading file:", err)
				}
				fmt.Println("Finished reading file.")
				close(semaphore)
				inputFile.Close()
				wg.Done()
				return
			}
		}
	}
}

// Hàm ghi kết quả vào file
func writeFiles(ctx context.Context, wg *sync.WaitGroup, results <-chan string, ouputFile string) {

	// Mở file để ghi kết quả
	file, err := os.OpenFile(ouputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening output file:", err)
		file.Close()
		wg.Done()
		return
	}

	for {
		select {
		case result, ok := <-results:
			if !ok {
				fmt.Println("hết write")
				file.Close()
				wg.Done()
				return
			}
			_, err := file.Write([]byte(result))
			if err != nil {
				fmt.Println("Error writing to file:", err)
			}
		case <-ctx.Done(): // Nếu nhận được tín hiệu hủy từ context
			fmt.Println("Context cancelled, stopping file write.")
			file.Close()
			wg.Done()
			return
		}
	}
}

func BruteDomainDNS(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string) {
	ips_reals, _ := net.LookupHost(domain)
	ips_real := ips_reals[0][0:6]
	var wg sync.WaitGroup
	var count int
	// Tạo semaphore và channel để nhận kết quả
	semaphore := make(chan string, maxChanSemaphore)
	results := make(chan string, maxChanResults)

	//Đọc wordlists từ file
	wg.Add(1)
	go readFiles(ctx, &wg, wordlist, semaphore)

	// Khởi động các goroutines để kiểm tra domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(ctx, &wg, semaphore, results, ips_real, domain, &count)
	}

	// Khởi động goroutine để ghi kết quả vào file output
	wg.Add(1)
	go writeFiles(ctx, &wg, results, "C:/Users/minhl/recon/src/data/output/output_domaindns.txt")

	// Chờ tất cả các goroutines hoàn thành
	wg.Wait()

}
