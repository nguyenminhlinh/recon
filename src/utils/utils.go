package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

//	func printOption(name []byte, value []byte) {
//		fmt.Fprintf(os.Stderr, " :: %-16s : %s\n", name, value)
//	}
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
