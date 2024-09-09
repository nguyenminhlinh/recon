package main

import (
	"fmt"
	"recon/collector/dir"
	"recon/collector/domain"
	"sync"
	"time"
)

func main() {
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		domain.BruteDomainDNS("dichvucong.gov.vn", "C:\\Users\\minhl\\recon\\src\\data\\input\\combined_subdomains.txt")
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		domain.FuffDomainHttp("dichvucong.gov.vn", "C:\\Users\\minhl\\recon\\src\\data\\input\\namelist.txt")
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		dir.FuffDir("dichvucong.gov.vn", "C:\\Users\\minhl\\recon\\src\\data\\input\\common.txt")
		wg.Done()
	}()
	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("Hoàn thành việc với thời gian", elapsed)
}
