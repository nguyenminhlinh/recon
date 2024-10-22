package output

import (
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

var OutputDirAndFile = make(map[string]int64)
var OutputDomain []string

func outPutFfuf(OutputFile string, res []ffuf.Result) error {
	OutputDirAndFile = map[string]int64{}
	OutputDomain = []string{}
	for _, r := range res {
		if OutputFile == "DirAndFileBruteForce" {
			OutputDirAndFile[r.Url] = r.ContentLength
		} else {
			OutputDomain = append(OutputDomain, r.Host)
		}
	}
	return nil
}
