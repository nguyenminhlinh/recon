package domain

import (
	"recon/utils"
	"strconv"
)

func DomainFfuf(domain string) {
	//Using the wrong host to get web content
	lengthResponse := utils.LengthResponse(domain, "abcdefghiklm."+domain)
	utils.Ffuf(domain, strconv.Itoa(lengthResponse), "C:/Users/minhl/recon/src/data/output_domain.json", "domain", true, 0, "C:/Users/minhl/recon/src/data/common.txt")
}
