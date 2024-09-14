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

	"github.com/fatih/color"
)

var (
	// Colors used to ease the reading of program output
	green = color.New(color.FgHiGreen).SprintFunc()
	red   = color.New(color.FgHiRed).SprintFunc()
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
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "BruteDomainDNS", red("Finished due to cancellation in "), elapsedBruteDomainDNS)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "BruteDomainDNS", green("Finished successfully in "), elapsedBruteDomainDNS)
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
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDomainHttp", red("Finished due to cancellation in "), elapsedFuffDomainHttp)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDomainHttp", green("Finished successfully in "), elapsedFuffDomainHttp)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		startFuffDirAndFile := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-16s : %s\n", "FuffDirAndFile", "Running....")
		dir.FuffDirAndFile(domainName, WorkDirectory+"/data/input/common.txt", WorkDirectory)
		elapsedFuffDirAndFile := time.Since(startFuffDirAndFile)
		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDirAndFile", red("Finished due to cancellation in "), elapsedFuffDirAndFile)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "FuffDirAndFile", green("Finished successfully in "), elapsedFuffDirAndFile)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		startAmassDomainOSINT := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-16s : %s\n", "AmassDomainOSINT", "Running....")
		domain.AmassDomainOSINT(ctx, cancel, domainName, WorkDirectory)
		elapsedAmassDomainOSINT := time.Since(startAmassDomainOSINT)
		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "AmassDomainOSINT", red("Finished due to cancellation in "), elapsedAmassDomainOSINT)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-16s : %s%v\n", "AmassDomainOSINT", green("Finished successfully in "), elapsedAmassDomainOSINT)
		}
		wg.Done()
	}()

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("\nComplete all missions within time", elapsed)
}
