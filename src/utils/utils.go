package utils

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// func LengthResponse(domain string, host string) int {
// 	req, err := http.NewRequest("GET", "https://"+domain, nil)
// 	if err != nil {
// 		fmt.Println("Error creating request:", err)
// 		os.Exit(1)
// 	}
// 	req.Host = host
// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		fmt.Println("Error sending request:", err)
// 		os.Exit(1)
// 	}
// 	defer resp.Body.Close()

// 	// Đọc header Content-Length
// 	contentLength := resp.Header.Get("Content-Length")
// 	if contentLength != "" {
// 		fmt.Println("Content-Length from header:", contentLength)
// 	}

// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println("Error reading response body:", err)
// 		os.Exit(1)
// 	}

//		return len(body)
//	}
// func LengthResponse(domain string, host string) int {
// 	req, err := http.NewRequest("GET", "https://"+domain, nil)
// 	if err != nil {
// 		fmt.Println("Error creating request:", err)
// 		os.Exit(1)
// 	}
// 	req.Host = host
// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		fmt.Println("Error sending request:", err)
// 		os.Exit(1)
// 	}
// 	defer resp.Body.Close()

// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println("Error reading response body:", err)
// 		os.Exit(1)
// 	}

// 	// Lưu nội dung response vào file để kiểm tra
// 	err = os.WriteFile("response_body.txt", body, 0644)
// 	if err != nil {
// 		fmt.Println("Error writing response body to file:", err)
// 		os.Exit(1)
// 	}

// 	return len(body)
// }

func LengthResponse(domain string, host string) int {
	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		os.Exit(1)
	}
	req.Host = host
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		os.Exit(1)
	}
	return len(body)
}

func ReadFiles(ctx context.Context, wg *sync.WaitGroup, file string, semaphore chan<- string, count *int, mu *sync.Mutex, maxgoroutines int) {
	defer wg.Done()
	inputFile, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			(*count)++
			if *count == maxgoroutines {
				close(semaphore) //Close the results channel after stop context
			}
			mu.Unlock()
			return //Context cancelled, stopping file read.
		default:
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					fmt.Println("Error reading file:", err)
				}
				mu.Lock()
				(*count)++
				if *count == maxgoroutines {
					close(semaphore) //Close the results channel after stop context
				}
				mu.Unlock()
				return //Read file finish
			}
			domain := scanner.Text()
			semaphore <- domain
		}
	}
}
func ReadJSONFile(filePath string) map[string]interface{} {
	// Đọc file JSON
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Đọc toàn bộ nội dung của file
	byteValue, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Parse nội dung file JSON thành map
	var data map[string]interface{}
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}
	return data
}

func WriteFiles(ctx context.Context, wg *sync.WaitGroup, results <-chan string, ouputFile string) {
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
			_, err := file.Write([]byte(result + "\n"))
			if err != nil {
				fmt.Println("Error writing to file:", err)
			}
		case <-ctx.Done():
			for len(results) > 0 {
				<-results
			}
			return //Context cancelled, stopping file write.
		}
	}
}

func Getwd() string {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		return ""
	}
	return filepath.ToSlash(cwd)
}
func CancelRun(cancel context.CancelFunc) bool {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("[WARN] Caught keyboard interrupt (Ctrl-C)")
		cancel() // Cancel all running goroutines
	}()
	return true
}

func UniqueLine(inputFile string, outputFile string) {
	// Mở file để đọc
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Tạo map để lưu các phần tử duy nhất
	uniqueLines := make(map[string]bool)

	// Đọc từng dòng trong file
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Thêm dòng vào map nếu chưa tồn tại
		if line != "" {
			uniqueLines[line] = true
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Mở file để ghi các phần tử duy nhất
	output, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer output.Close()

	// Ghi các phần tử duy nhất vào file
	for line := range uniqueLines {
		_, err := output.WriteString(line + "\n")
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
}

func AllDomain(ctx context.Context, WorkDirectory string, Domain string) {
	data := ReadJSONFile(WorkDirectory + "/data/output/FuffDomainHttp.json")

	results, ok := data["results"].([]interface{})
	if !ok {
		log.Fatalf("Error: 'results' is not a valid array")
	}
	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex
	outputChan := make(chan string, 50)
	wg.Add(1)
	go WriteFiles(ctx, &wg, outputChan, WorkDirectory+"/data/output/AllDomain.txt")
	for _, result := range results {
		resultMap := result.(map[string]interface{})
		outputChan <- resultMap["input"].(map[string]interface{})["FUZZ"].(string) + "." + Domain
	}
	wg.Add(1)
	go ReadFiles(ctx, &wg, WorkDirectory+"/data/output/SubfinderDomainOSINT.txt", outputChan, &count, &mu, 3)
	wg.Add(1)
	go ReadFiles(ctx, &wg, WorkDirectory+"/data/output/BruteDomainDNS.txt", outputChan, &count, &mu, 3)
	wg.Add(1)
	go ReadFiles(ctx, &wg, WorkDirectory+"/data/output/AmassDomainOSINT.txt", outputChan, &count, &mu, 3)
	wg.Wait()
	UniqueLine(WorkDirectory+"/data/output/AllDomain.txt", WorkDirectory+"/data/output/AllDomainUnique.txt")
}
