package dir

import (
	"context"
	"recon/utils"
	"strconv"
)

func FuffDir(ctx context.Context, cancel context.CancelFunc, domain string, wordlist string) {
	//Using the wrong tail to get web content
	lengthResponse := utils.LengthResponse(domain+"/abcdefghiklm", "")
	utils.Ffuf(ctx, cancel, domain, strconv.Itoa(lengthResponse), "C:/Users/minhl/recon/src/data/output/output_dir.json", "dir", false, 0, wordlist)
}
