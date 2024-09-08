package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// func main() {
// 	var wg sync.WaitGroup
// 	//key := new(sync.Mutex)

// 	// wg.Add(1)
// 	// go func() {
// 	// 	// domain.DomainFfuf("dichvucong.gov.vn")
// 	// 	wg.Done()
// 	// }()
// 	// wg.Add(1)
// 	// go func() {
// 	// 	dir.DirFfuf("dichvucong.gov.vn")
// 	// 	wg.Done()
// 	// }()
// 	//fmt.Print(utils.LengthResponse("dichvucong.gov.vn", "testapigw."+"dichvucong.gov.vn"))
// 	ips_fakers, err_faker := net.LookupHost("abcdefghiklmno123456789.dichvucong.gov.vn")
// 	domain := []string{"sdfsdfsdf.dichvucong.gov.vn", "dsfsdf.dichvucong.gov.vn", "sdfsdfsdfsdf.dichvucong.gov.vn", "fgdf.dichvucong.gov.vn", "testmobile.dichvucong.gov.vn", "chatbot.dichvucong.gov.vn", "mail.dichvucong.gov.vn", "testdangky.dichvucong.gov.vn", "testapigw.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn", "ftp.dichvucong.gov.vn"}
// 	for i := 1; i < 10; i++ {
// 		wg.Add(1)
// 		go func() {
// 			for j := 1; j < 10; j++ {
// 				//key.Lock()
// 				ips, err := net.LookupHost(domain[i])
// 				if err != nil {
// 					fmt.Println("không") // Domain không tồn tại
// 				} else {
// 					if err_faker == nil {
// 						flag := true
// 						for _, ip := range ips {
// 							if ips_fakers[0] == ip {
// 								flag = false
// 								break
// 							}
// 						}
// 						if flag {
// 							fmt.Println(domain[i]) // Domain tồn tại
// 							fmt.Println(ips)
// 						} else {
// 							fmt.Println("không") // Domain không tồn tại
// 						}
// 					} else if err != nil {
// 						fmt.Println(domain[i]) // Domain tồn tại
// 						fmt.Println(ips)
// 					}
// 				}
// 				//key.Unlock()
// 			}
// 			wg.Done()
// 		}()
// 	}

// 	wg.Wait()
// }

const maxGoroutines = 5 // Giới hạn số lượng goroutine đồng thời

// Hàm kiểm tra domain
func checkDomain(wg *sync.WaitGroup, semaphore chan string, count *int, key *sync.Mutex) {
	defer wg.Done() // Giảm giá trị của WaitGroup khi goroutine hoàn thành
	for domain := range semaphore {
		key.Lock()
		*count++

		ips_fakers, err_fakers := net.LookupHost("dichvucong.gov.vn")
		ips, err := net.LookupHost(domain + ".dichvucong.gov.vn")
		key.Unlock()
		flag := true
		if err_fakers == nil && err == nil {
			if ips_fakers[0] == ips[0] {
				flag = false
			}
		} else if err != nil {
			flag = false
		}
		if flag {
			fmt.Println("Domain tồn tại: ", domain, " ", err, " ", ips)
			fmt.Println("Fake: ", domain, " ", err_fakers, " ", ips_fakers)
			//fmt.Println(ips)
		} else {
			//fmt.Println(domain, " ", err) // Domain không tồn tại
		}
		if domain == "csdl" {
			fmt.Println(*count, "**************************************************", err, " ", ips)
		}
	}
}

// Hàm đọc domain từ file
func readFiles(wg *sync.WaitGroup, filename string, semaphore chan<- string) {
	defer wg.Done()
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
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

func main() {
	start := time.Now()

	var count int
	var wg sync.WaitGroup
	key := new(sync.Mutex)
	// Tạo semaphore và channel để nhận kết quả
	semaphore := make(chan string, 100)
	wg.Add(1)
	go readFiles(&wg, "C:\\Users\\minhl\\recon\\src\\data\\combined_subdomains.txt", semaphore)

	// Khởi động các goroutines để kiểm tra domain
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go checkDomain(&wg, semaphore, &count, key)
	}
	// Chờ tất cả các goroutines hoàn thành
	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("Hoàn thành việc kiểm tra domain với thời gian", elapsed, "và ", count)
}
