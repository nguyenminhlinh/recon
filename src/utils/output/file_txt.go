package output

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

func writeTxt(filename string, OutputFile string, res []ffuf.Result) error {
	file, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, r := range res {
		if strings.Contains(OutputFile, "DirAndFileBruteForce") {
			_, err = file.Write([]byte(r.Url + "\n" + strconv.FormatInt(r.ContentLength, 10) + "\n"))
			if err != nil {
				fmt.Println("Error writing to file:", err)
			}
		} else {
			_, err = file.Write([]byte(r.Host + "\n"))
			if err != nil {
				fmt.Println("Error writing to file:", err)
			}
		}
	}
	return nil
}
