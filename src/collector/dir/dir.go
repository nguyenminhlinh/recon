package dir

import (
	"recon/utils"
	"strconv"
)

func FuffDirAndFile(domain string, wordlist string, WorkDirectory string) {
	//Using the wrong tail to get web content
	lengthResponse := utils.LengthResponse(domain+"/abcdefghiklm", "")
	utils.Ffuf(domain, strconv.Itoa(lengthResponse), WorkDirectory+"/data/output/FuffDirAndFile.json", "dir", false, 0, wordlist)
}
