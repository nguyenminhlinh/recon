package dir

import (
	"recon/utils"
	"strconv"
)

func FuffDir(domain string, wordlist string) {
	//Using the wrong tail to get web content
	lengthResponse := utils.LengthResponse(domain+"/abcdefghiklm", "")
	utils.Ffuf(domain, strconv.Itoa(lengthResponse), "C:/Users/minhl/recon/src/data/output/output_dir.json", "dir", false, 0, wordlist)
}
