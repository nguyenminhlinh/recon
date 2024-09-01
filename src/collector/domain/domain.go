package domain

import (
	"recon/utils"
)

func DomainFfuf(domain string) {
	utils.FfufWithMulFunc(domain, "C:/Users/minhl/recon/src/data/output_domain.json", "domain", true)
	// utils.Ffuf(domain, "0", "C:/Users/minhl/recon/src/data/output_domain.json", "domain", true, 0)
}
