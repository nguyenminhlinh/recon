package output

import (
	"fmt"
	"os"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// type JsonResult struct {
// 	Input            map[string]string   `json:"input"`
// 	Position         int                 `json:"position"`
// 	StatusCode       int64               `json:"status"`
// 	ContentLength    int64               `json:"length"`
// 	ContentWords     int64               `json:"words"`
// 	ContentLines     int64               `json:"lines"`
// 	ContentType      string              `json:"content-type"`
// 	RedirectLocation string              `json:"redirectlocation"`
// 	ScraperData      map[string][]string `json:"scraper"`
// 	Duration         time.Duration       `json:"duration"`
// 	ResultFile       string              `json:"resultfile"`
// 	Url              string              `json:"url"`
// 	Host             string              `json:"host"`
// }

func write(filename string, config *ffuf.Config, res []ffuf.Result) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, r := range res {
		for k, v := range r.Input {
			if k == "FUZZ" {
				_, err = file.Write([]byte(string(v) + "\n"))
				if err != nil {
					fmt.Println("Error writing to file:", err)
				}
			}
		}
	}
	return nil
}
