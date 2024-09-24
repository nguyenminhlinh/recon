package port

import (
	"context"
	"log"
	data "recon/data/type"
	"recon/utils/runner"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

func ScanPortAndService(subDomain string, infoSubDomain *data.InfoSubDomain) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var scanPortAndService string
	var ports []*port.Port
	options := runner.Options{
		Host:     goflags.StringSlice{subDomain},
		ScanType: "s",
		TopPorts: "1000",
		Nmap:     true,
		NmapCLI:  "nmap -O -sV",
		Silent:   true,
		OnResult: func(hr *result.HostResult) {
			// fmt.Println(hr.Host, hr.Ports)
			ports = hr.Ports
		},
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer naabuRunner.Close()

	err = naabuRunner.RunEnumeration(ctx, &scanPortAndService)
	if err != nil {
		for _, port := range ports {
			infoSubDomain.PortAndService = append(infoSubDomain.PortAndService, strconv.Itoa(port.Port))
		}
	} else {
		numberPort := len(ports)
		// fmt.Println(numberhPort)
		instances := strings.TrimSpace(scanPortAndService)

		if instances != "" {
			flagCopyPort := false
			count := 0
			for _, instance := range strings.Split(instances, "\r\n") {
				instance = strings.TrimSpace(instance)
				// fmt.Println("*", instance, "*")
				if flagCopyPort && count < numberPort {
					infoSubDomain.PortAndService = append(infoSubDomain.PortAndService, instance)
					count++
				}
				if strings.Contains(instance, "PORT") {
					flagCopyPort = true
				}
			}
		}
	}
}
