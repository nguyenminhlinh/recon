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

func LengthResponse(domain string, host string) (int, bool) {
	var flaghttp = false

	// Create request for HTTPS
	reqhttps, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		return 0, false
	}
	reqhttps.Host = host

	// Create request for HTTP
	reqhttp, err := http.NewRequest("GET", "http://"+domain, nil)
	if err != nil {
		return 0, false
	}
	reqhttp.Host = host

	client := &http.Client{}

	// Send request for HTTPS
	resp, err := client.Do(reqhttps)
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, false
		}
		return len(body), false // No need to send HTTP if HTTPS is successful
	} else {
		flaghttp = true
	}

	// Send HTTP request if HTTPS fails
	if flaghttp {
		resp, err = client.Do(reqhttp)
		if err != nil {
			return 0, true
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, true
		}

		return len(body), true
	}

	return 0, false // Returns 0 if both requests fail
}

func ReadFilesSimple(file string) string {
	// Open the file to read
	inputFile, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return ""
	}
	defer inputFile.Close()

	// Read the entire file content into the variable
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
	// Read file JSON
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Read the entire content of the file
	byteValue, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Parse JSON file content into map
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
	// Channel to capture signals from the operating system
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Create a WaitGroup to wait for goroutines to complete
	// Capture signal Ctrl+C
	go func() {
		<-stopChan
		fmt.Println("Received an interrupt, stopping...")
		os.Exit(1) // Exit the program immediately
	}()
}

func HasRootPrivilege() bool {
	return true
}