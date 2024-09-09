package domain

import (
	"bufio"
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
func checkDomain(wg *sync.WaitGroup, semaphore chan string, results chan<- string, ips_real string, domain string) {
	defer wg.Done() // Giảm giá trị của WaitGroup khi goroutine hoàn thành
	for subdomain := range semaphore {
		ips, err := net.LookupHost(subdomain + "." + domain)
		if err == nil {
			if ips[0][0:6] == ips_real {
				fmt.Fprintf(os.Stdout, "Subdomain tồn tại:: %-35s : %-16s : %s\n", subdomain, err, ips)
				results <- subdomain + "\n"
			}
		}
	}
}

// Hàm đọc domain từ file
func readFiles(wg *sync.WaitGroup, filename string, semaphore chan<- string) {
	defer wg.Done()
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		close(semaphore)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		semaphore <- domain // Gửi domain vào channel semaphore để kiểm tra
	}
	close(semaphore)
}

// Hàm ghi kết quả vào file
func writeFiles(wg *sync.WaitGroup, results <-chan string, file *os.File) {
	defer wg.Done()
	for result := range results {
		_, err := file.Write([]byte(result))
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}
}

func BruteDomainDNS(domain string, wordlist string) {
	ips_reals, _ := net.LookupHost(domain)
	ips_real := ips_reals[0][0:6]
	var wg sync.WaitGroup

	// Tạo semaphore và channel để nhận kết quả
	semaphore := make(chan string, maxChanSemaphore)
	results := make(chan string, maxChanResults)

	//Đọc wordlists từ file
	wg.Add(1)
	go readFiles(&wg, wordlist, semaphore)

	// Khởi động các goroutines để kiểm tra domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(&wg, semaphore, results, ips_real, domain)
	}

	// Mở file để ghi kết quả
	outputFile, err := os.OpenFile("C:/Users/minhl/recon/src/data/output/output_domaindns.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening output file:", err)
		return
	}
	defer outputFile.Close()
	// Khởi động goroutine để ghi kết quả vào file
	wg.Add(1)
	go writeFiles(&wg, results, outputFile)

	// Chờ tất cả các goroutines hoàn thành
	wg.Wait()

	// Đóng channel results sau khi các goroutine hoàn thành
	close(results)
}
