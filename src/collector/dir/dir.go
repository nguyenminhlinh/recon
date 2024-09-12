package dir

import (
	"context"
	"recon/utils"
	"strconv"
)

func FuffDirAndFile(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string, WorkDirectory string) {
	//Using the wrong tail to get web content
	lengthResponse := utils.LengthResponse(domain+"/abcdefghiklm", "")
	utils.Ffuf(ctx, cancel, domain, strconv.Itoa(lengthResponse), WorkDirectory+"/data/output/FuffDirAndFile.json", "dir", false, 0, wordlist)
}
