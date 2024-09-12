package main

import (
	"context"
	"fmt"
	"recon/collector/dir"
	"recon/collector/domain"
	"sync"
	"time"
)

func main() {
	start := time.Now()
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg.Add(1)
	go func() {
		domain.BruteDomainDNS(ctx, cancel, "google.com", "C:\\Users\\minhl\\recon\\src\\data\\input\\combined_subdomains.txt") //combined_subdomains
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		domain.FuffDomainHttp(ctx, cancel, "google.com", "C:\\Users\\minhl\\recon\\src\\data\\input\\namelist.txt")
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		dir.FuffDir(ctx, cancel, "google.com", "C:\\Users\\minhl\\recon\\src\\data\\input\\common.txt")
		wg.Done()
	}()

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("Hoàn thành việc với thời gian", elapsed)
}
