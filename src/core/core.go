package core

import (
	"context"
	"fmt"
	"os"
	"recon/collector/dir"
	"recon/collector/domain"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	// Colors used to ease the reading of program output
	green = color.New(color.FgHiGreen).SprintFunc()
	red   = color.New(color.FgHiRed).SprintFunc()
)

func Core(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, domainName string, workDirectory string, nameFunc string) {
	wg.Add(1)
	go func() {
		start := time.Now()
		fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", nameFunc, "Running....")

		if nameFunc == "DomainBruteForceHttp" {
			domain.DomainBruteForceHttp(domainName, workDirectory+"/data/input/subdomains-top1mil-110000.txt", workDirectory)
		} else if nameFunc == "DomainBruteForceDNS" {
			domain.DomainBruteForceDNS(ctx, cancel, domainName, workDirectory+"/data/input/subdomains-top1mil-110000.txt", workDirectory) //combined_subdomains
		} else if nameFunc == "DomainOSINTAmass" {
			domain.DomainOSINTAmass(ctx, cancel, domainName, workDirectory)
		} else if nameFunc == "DomainOSINTSubfinder" {
			domain.DomainOSINTSubfinder(ctx, cancel, domainName, workDirectory)
		} else if nameFunc == "DirAndFileBruteForce" {
			dir.DirAndFileBruteForce(ctx, domainName, workDirectory+"/data/input/common.txt", workDirectory)
		}

		elapsed := time.Since(start)

		select {
		case <-ctx.Done():
			// If a signal is received from the context
			fmt.Fprintf(os.Stderr, "[*] %-22s : %s%v\n", nameFunc, red("Finished due to cancellation in "), elapsed)
		default:
			// If there is no cancel signal, take another action
			fmt.Fprintf(os.Stderr, "[*] %-22s : %s%v\n", nameFunc, green("Finished successfully in "), elapsed)
		}
		wg.Done()
	}()
}
