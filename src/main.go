package main

import (
	"recon/collector/dir"
	"recon/collector/domain"
	"sync"
)

func main() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		domain.DomainFfuf("dichvucong.gov.vn")
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		dir.DirFfuf("dichvucong.gov.vn")
		wg.Done()
	}()
	//fmt.Print(utils.LengthResponse("gumac.vn/dsads", ""))
	wg.Wait()
}
