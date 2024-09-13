package main

import (
	"context"
	"fmt"
	"os"
	"recon/collector/dir"
	"recon/collector/domain"
	"recon/utils"
	"sync"
	"time"
)

const (
	BANNER_HEADER = `
 █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║██║   ██║   ██║   ██║   ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝`
	BANNER_SEP = "__________________________________________________________________________________"
)

func main() {
	start := time.Now()
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	utils.CancelRun(cancel)

	// Get command from console
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <domain>")
		os.Exit(1)
	}
	domainName := os.Args[1]

	fmt.Fprintf(os.Stderr, "%s\n       %+60s\n%s\n", BANNER_HEADER, "Made by MinhLinh", BANNER_SEP)
	fmt.Fprintf(os.Stderr, "[*] %-16s : %s\n", "Scanning target", domainName)
	WorkDirectory := utils.Getwd()

	wg.Add(1)
	go func() {
		startBruteDomainDNS := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-16s : %s\n", "BruteDomainDNS", "Running....")
		domain.BruteDomainDNS(ctx, cancel, domainName, WorkDirectory+"/data/input/combined_subdomains.txt", WorkDirectory) //combined_subdomains
		elapsedBruteDomainDNS := time.Since(startBruteDomainDNS)
		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "BruteDomainDNS", "Finished due to cancellation in ", elapsedBruteDomainDNS)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "BruteDomainDNS", "Finished successfully in ", elapsedBruteDomainDNS)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		startFuffDomainHttp := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-16s : %s\n", "FuffDomainHttp", "Running....")
		domain.FuffDomainHttp(domainName, WorkDirectory+"/data/input/namelist.txt", WorkDirectory)
		elapsedFuffDomainHttp := time.Since(startFuffDomainHttp)
		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDomainHttp", "Finished due to cancellation in ", elapsedFuffDomainHttp)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDomainHttp", "Finished successfully in ", elapsedFuffDomainHttp)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		startFuffDirAndFile := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-16s : %s\n", "FuffDir", "Running....")
		dir.FuffDirAndFile(domainName, WorkDirectory+"/data/input/common.txt", WorkDirectory)
		elapsedFuffDirAndFile := time.Since(startFuffDirAndFile)
		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDir", "Finished due to cancellation in ", elapsedFuffDirAndFile)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDir", "Finished successfully in ", elapsedFuffDirAndFile)
		}
		wg.Done()
	}()

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("\nComplete all missions within time", elapsed)
}
