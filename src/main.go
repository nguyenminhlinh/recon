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
	// c := make(chan os.Signal, 1)
	// signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// wg.Add(1)
	// go func() {
	// 	<-c
	// 	fmt.Println("Received Ctrl+C, canceling all tasks...")
	// 	cancel() // Hủy tất cả các goroutine đang chạy
	// 	wg.Done()
	// }()
	wg.Add(1)
	go func() {
		domain.BruteDomainDNS(ctx, cancel, "dichvucong.gov.vn", "C:\\Users\\minhl\\recon\\src\\data\\input\\combined_subdomains.txt")
		fmt.Println("17")
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		domain.FuffDomainHttp("dichvucong.gov.vn", "C:\\Users\\minhl\\recon\\src\\data\\input\\namelist.txt")
		fmt.Println("linh")
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		dir.FuffDir("dichvucong.gov.vn", "C:\\Users\\minhl\\recon\\src\\data\\input\\common.txt")
		wg.Done()
	}()
	// Bắt tín hiệu Ctrl+C từ người dùng

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("Hoàn thành việc với thời gian", elapsed)
}
