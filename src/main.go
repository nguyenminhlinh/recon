package main

import (
	"context"
	"fmt"
	"os"
	"recon/core"
	"recon/utils"
	"sync"
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
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	utils.CancelRun(cancel)
	workDirectory := utils.Getwd()

	// Get command from console
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <domain>")
		os.Exit(1)
	}
	domainName := os.Args[1]

	fmt.Fprintf(os.Stderr, "%s\n       %+60s\n%s\n", BANNER_HEADER, "Made by MinhLinh", BANNER_SEP)
	fmt.Fprintf(os.Stderr, "[*] %-22s : %s\n", "Scanning target", domainName)

	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainBruteForceHttp")
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainBruteForceDNS")
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainOSINTAmass")
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DomainOSINTSubfinder")
	core.Core(ctx, cancel, &wg, domainName, workDirectory, "DirAndFileBruteForce")

	wg.Wait()
	//utils.AllDomain(ctx, workDirectory, domainName)
	fmt.Println("\nComplete all missions ")
}
