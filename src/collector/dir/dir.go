package dir

import (
	"recon/utils"
	"strconv"
)

func DirFfuf(domain string) {
	//Using the wrong tail to get web content
	lengthResponse := utils.LengthResponse(domain+"/abcdefghiklm", "")
	utils.Ffuf(domain, strconv.Itoa(lengthResponse), "C:/Users/minhl/recon/src/data/output_dir.json", "dir", true, 0)
}
