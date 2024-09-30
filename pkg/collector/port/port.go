package port

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	data "recon/pkg/data/type"
	"recon/pkg/utils"
	"recon/pkg/utils/runner"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	osutil "github.com/projectdiscovery/utils/os"
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

func isCommandExecutable(args []string) bool {
	commandLength := calculateCmdLength(args)
	if osutil.IsWindows() {
		// windows has a hard limit of
		// - 2048 characters in XP
		// - 32768 characters in Win7
		return commandLength < 2048
	}
	// linux and darwin
	return true
}

func calculateCmdLength(args []string) int {
	var commandLength int
	for _, arg := range args {
		commandLength += len(arg)
		commandLength += 1 // space character
	}
	return commandLength
}

func nmap(nmapCLI string) bool {
	args := strings.Split(nmapCLI, " ")
	commandCanBeExecuted := isCommandExecutable(args)
	if commandCanBeExecuted {
		posArgs := 0
		nmapCommand := "nmap"
		if args[0] == "nmap" || args[0] == "nmap.exe" {
			posArgs = 1
		}

		// if it's windows search for the executable
		if osutil.IsWindows() {
			nmapCommand = "nmap.exe"
		}

		cmd := exec.Command(nmapCommand, args[posArgs:]...)

		err := cmd.Run()
		if err != nil {
			fmt.Println("Could not run nmap command", err)
			return false
		} else {
			return true
		}
	}
	return false
}

func ScanPortAndService(subDomain string, infoSubDomain *data.InfoSubDomain, workDirectory string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	randomNumber := rand.Intn(1000) + 1 // Generate random numbers between 1 and 100
	var ports []*port.Port
	nmapCLI := "nmap -O -sV -top-ports 1000 -oX " + workDirectory + "/pkg/data/output/scanPortAndService" + strconv.Itoa(randomNumber) + ".txt " + subDomain

	if infoSubDomain.PortAndService == nil {
		infoSubDomain.PortAndService = make(map[string]string)
	}

	if nmap(nmapCLI) { //If have nmap on device and complete run
		output := utils.ReadFilesSimple(workDirectory + "/pkg/data/output/scanPortAndService" + strconv.Itoa(randomNumber) + ".txt")
		// remove file
		err := os.Remove(workDirectory + "/pkg/data/output/scanPortAndService" + strconv.Itoa(randomNumber) + ".txt")
		if err != nil {
			fmt.Println("Error when deleting files:", err)
			return
		}
		instances := strings.TrimSpace(output)

		if instances != "" {
			flagGetType := false
			os := ""
			for _, instance := range strings.Split(instances, "\r\n") {
				instance = strings.TrimSpace(instance)
				if strings.Contains(instance, "<port protocol") {
					instance = strings.TrimPrefix(instance, "<ports>") // Use TrimPrefix to remove <ports>
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
					err := xml.Unmarshal([]byte(instance), &osMatch)
					if err != nil {
						fmt.Println("Error osmatch decoding XML:", err)
						return
					}
					os = "Name:" + osMatch.Name + " (" + osMatch.Accuracy + "%)"
					flagGetType = true
				}

				if strings.Contains(instance, "<osclass") && flagGetType {
					var osClass OsClass
					err := xml.Unmarshal([]byte(instance), &osClass)
					if err != nil {
						fmt.Println("Error osclass decoding XML:", err)
						return
					}
					infoSubDomain.Os = append(infoSubDomain.Os, os+" Devicetype:"+osClass.Type)
					flagGetType = false
				}
			}
		}
	} else { //Use Naabu to scan port
		options := runner.Options{
			Host:     goflags.StringSlice{subDomain},
			ScanType: "s",
			Silent:   true,
			OnResult: func(hr *result.HostResult) {
				ports = hr.Ports
			},
		}

		naabuRunner, err := runner.NewRunner(&options)
		if err != nil {
			log.Fatal(err)
		}
		defer naabuRunner.Close()

		naabuRunner.RunEnumeration(ctx)

		for _, port := range ports {
			infoSubDomain.PortAndService[strconv.Itoa(port.Port)] = ""
		}
	}
}
