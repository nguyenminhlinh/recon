package utils

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

func ReadFiles(ctx context.Context, wg *sync.WaitGroup, file string, semaphore chan<- string) {
	defer wg.Done()
	defer close(semaphore)
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
			_, err := file.Write([]byte(result))
			if err != nil {
				fmt.Println("Error writing to file:", err)
			}
		case <-ctx.Done():
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
