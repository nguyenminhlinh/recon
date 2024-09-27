package port

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"math/rand"
	"os"
	data "recon/data/type"
	"recon/utils"
	"recon/utils/runner"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

type OsMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}
type OsClass struct {
	Type string `xml:"type,attr"`
}
type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

type State struct {
	State string `xml:"state,attr"`
}

type Service struct {
	Name    string `xml:"name,attr"`
	Tunnel  string `xml:"tunnel,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func ScanPortAndService(subDomain string, infoSubDomain *data.InfoSubDomain, workDirectory string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Generate random numbers between 1 and 100
	randomNumber := rand.Intn(100) + 1
	var scanPortAndService string
	var ports []*port.Port
	nmapCLI := "nmap -O -sV -oX " + workDirectory + "/data/output/scanPortAndService" + strconv.Itoa(randomNumber) + ".txt"
	options := runner.Options{
		Host:     goflags.StringSlice{subDomain},
		ScanType: "s",
		TopPorts: "1000",
		Nmap:     true,
		NmapCLI:  nmapCLI,
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
	if infoSubDomain.PortAndService == nil {
		infoSubDomain.PortAndService = make(map[string]string)
	}
	if err != nil {
		for _, port := range ports {
			infoSubDomain.PortAndService[strconv.Itoa(port.Port)] = ""
		}
	} else {
		output := utils.ReadFilesSimple(workDirectory + "/data/output/scanPortAndService" + strconv.Itoa(randomNumber) + ".txt")

		instances := strings.TrimSpace(output)

		if instances != "" {
			flagCopyPort := false
			os := ""
			for _, instance := range strings.Split(instances, "\r\n") {
				instance = strings.TrimSpace(instance)
				if strings.Contains(instance, "<port protocol") {
					// Use TrimPrefix to remove <ports>
					instance = strings.TrimPrefix(instance, "<ports>")
					var port Port
					err := xml.Unmarshal([]byte(instance), &port)
					if err != nil {
						fmt.Println("Error port protocol:", err)
						return
					}
					service := ""
					if port.Service.Tunnel != "" {
						service = port.Service.Tunnel + "/" + port.Service.Name
					} else {
						service = port.Service.Name
					}
					infoSubDomain.PortAndService[port.PortID] = "Port:" + port.PortID + "/" + port.Protocol + " State:" + port.State.State + " Service:" + service + " Version:" + port.Service.Product + " " + port.Service.Version
				}
				if strings.Contains(instance, "<osmatch") {
					instance = instance + "</osmatch>"
					var osMatch OsMatch
					// Giải mã XML
					err := xml.Unmarshal([]byte(instance), &osMatch)
					if err != nil {
						fmt.Println("Error osmatch decoding XML:", err)
						return
					}
					os = "Name:" + osMatch.Name + " (" + osMatch.Accuracy + "%)"
					flagCopyPort = true
				}
				if strings.Contains(instance, "<osclass") && flagCopyPort {
					var osClass OsClass
					// Giải mã XML
					err := xml.Unmarshal([]byte(instance), &osClass)
					if err != nil {
						fmt.Println("Error osclass decoding XML:", err)
						return
					}
					infoSubDomain.Os = append(infoSubDomain.Os, os+" Devicetype:"+osClass.Type)
					flagCopyPort = false
				}
			}
		}
		// remove file
		err := os.Remove(workDirectory + "/data/output/scanPortAndService" + strconv.Itoa(randomNumber) + ".txt")
		if err != nil {
			fmt.Println("Error when deleting files:", err)
			return
		}
	}
}
