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
	"sync"
	"syscall"
)

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
func ReadFilesSimple(file string) string {
	// Mở file để đọc
	inputFile, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return ""
	}
	defer inputFile.Close()

	// Đọc toàn bộ nội dung file vào biến
	content, err := io.ReadAll(inputFile)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return ""
	}
	return string(content)
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

func StopRun() {
	// Channel để bắt tín hiệu từ hệ điều hành
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Tạo WaitGroup để chờ các goroutines hoàn thành
	// Bắt tín hiệu Ctrl+C
	go func() {
		<-stopChan
		fmt.Println("Received an interrupt, stopping...")
		os.Exit(1) // Thoát khỏi chương trình ngay lập tức
	}()
}

// func Httpx(wg *sync.WaitGroup, domain string, InfoDomain *data.InfoDomain) {
// 	// Channel để bắt tín hiệu từ hệ điều hành
// 	stopChan := make(chan os.Signal, 1)
// 	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

// 	// Tạo WaitGroup để chờ các goroutines hoàn thà
// 	// Bắt tín hiệu Ctrl+C
// 	go func() {
// 		<-stopChan
// 		fmt.Println("Received an interrupt, stopping...")
// 		os.Exit(1) // Thoát khỏi chương trình ngay lập tức
// 	}()
// 	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)
// 	//gologger.Silent()
// 	apiEndpoint := "127.0.0.1:31234"

// 	options := runnerhttpx.Options{
// 		Methods:         "GET",
// 		InputTargetHost: goflags.StringSlice{domain},
// 		Threads:         1,
// 		HttpApiEndpoint: apiEndpoint,
// 		OnResult: func(r runnerhttpx.Result) {
// 			// handle error
// 			if r.Err != nil {
// 				fmt.Printf("[Err] %s: %s\n", r.Input, r.Err)
// 				return
// 			}
// 			fmt.Printf("%s * %d * %s \n", r.Input, r.StatusCode, r.Title)
// 			fmt.Println("12")
// 			infoWeb := data.InfoWeb{}
// 			if InfoDomain.HttpOrHttps == nil {
// 				InfoDomain.HttpOrHttps = make(map[string]data.InfoWeb)
// 			}
// 			if infoWeb.TechnologyDetails == nil {
// 				infoWeb.TechnologyDetails = make(map[string]wappalyzer.AppInfo)
// 			}
// 			fmt.Println("13")
// 			for key, value := range r.TechnologyDetails {
// 				infoWeb.TechnologyDetails[key] = value
// 			}
// 			InfoDomain.HttpOrHttps[r.URL] = infoWeb
// 			fmt.Println("14", infoWeb)
// 		},
// 	}

// 	// after 3 seconds increase the speed to 50
// 	time.AfterFunc(3*time.Second, func() {
// 		client := &http.Client{}

// 		concurrencySettings := runnerhttpx.Concurrency{Threads: 20}
// 		requestBody, err := json.Marshal(concurrencySettings)
// 		if err != nil {
// 			log.Fatalf("Error creating request body: %v", err)
// 		}

// 		req, err := http.NewRequest("PUT", fmt.Sprintf("http://%s/api/concurrency", apiEndpoint), bytes.NewBuffer(requestBody))
// 		if err != nil {
// 			log.Fatalf("Error creating PUT request: %v", err)
// 		}
// 		req.Header.Set("Content-Type", "application/json")

// 		resp, err := client.Do(req)
// 		if err != nil {
// 			log.Fatalf("Error sending PUT request: %v", err)
// 		}
// 		defer resp.Body.Close()

// 		if resp.StatusCode != http.StatusOK {
// 			log.Printf("Failed to update threads, status code: %d", resp.StatusCode)
// 		} else {
// 			log.Println("Threads updated to 20 successfully")
// 		}
// 	})

// 	if err := options.ValidateOptions(); err != nil {
// 		log.Fatal(err)
// 	}

// 	httpxRunner, err := runnerhttpx.New(&options)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer httpxRunner.Close()

// 	httpxRunner.RunEnumeration()
// }

// func Httpx1(outChans chan string, domain []string) {
// 	// Channel để bắt tín hiệu từ hệ điều hành
// 	stopChan := make(chan os.Signal, 1)
// 	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

// 	// Tạo WaitGroup để chờ các goroutines hoàn thà
// 	// Bắt tín hiệu Ctrl+C
// 	go func() {
// 		<-stopChan
// 		fmt.Println("Received an interrupt, stopping...")
// 		os.Exit(1) // Thoát khỏi chương trình ngay lập tức
// 	}()
// 	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)
// 	//gologger.Silent()
// 	apiEndpoint := "127.0.0.1:31234"

// 	options := runnerhttpx.Options{
// 		Methods:         "GET",
// 		InputTargetHost: goflags.StringSlice(domain),
// 		Threads:         1,
// 		HttpApiEndpoint: apiEndpoint,
// 		OnResult: func(r runnerhttpx.Result) {
// 			// handle error
// 			if r.Err != nil {
// 				fmt.Printf("[Err] %s: %s\n", r.Input, r.Err)
// 				return
// 			}
// 			fmt.Printf("%s * %d * %s \n", r.Input, r.StatusCode, r.Title)
// 			outChans <- r.Input
// 		},
// 	}

// 	// after 3 seconds increase the speed to 50
// 	time.AfterFunc(3*time.Second, func() {
// 		client := &http.Client{}

// 		concurrencySettings := runnerhttpx.Concurrency{Threads: 20}
// 		requestBody, err := json.Marshal(concurrencySettings)
// 		if err != nil {
// 			log.Fatalf("Error creating request body: %v", err)
// 		}

// 		req, err := http.NewRequest("PUT", fmt.Sprintf("http://%s/api/concurrency", apiEndpoint), bytes.NewBuffer(requestBody))
// 		if err != nil {
// 			log.Fatalf("Error creating PUT request: %v", err)
// 		}
// 		req.Header.Set("Content-Type", "application/json")

// 		resp, err := client.Do(req)
// 		if err != nil {
// 			log.Fatalf("Error sending PUT request: %v", err)
// 		}
// 		defer resp.Body.Close()

// 		if resp.StatusCode != http.StatusOK {
// 			log.Printf("Failed to update threads, status code: %d", resp.StatusCode)
// 		} else {
// 			log.Println("Threads updated to 20 successfully")
// 		}
// 	})

// 	if err := options.ValidateOptions(); err != nil {
// 		log.Fatal(err)
// 	}

// 	httpxRunner, err := runnerhttpx.New(&options)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer httpxRunner.Close()

// 	httpxRunner.RunEnumeration()
// }
