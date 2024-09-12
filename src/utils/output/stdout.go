package output

import (
	"crypto/md5"
	"fmt"
	"os"
	"path"
	"sort"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

type Stdoutput struct {
	config         *ffuf.Config
	fuzzkeywords   []string
	Results        []ffuf.Result
	CurrentResults []ffuf.Result
}

func NewStdoutput(conf *ffuf.Config) *Stdoutput {
	var outp Stdoutput
	outp.config = conf
	outp.Results = make([]ffuf.Result, 0)
	outp.CurrentResults = make([]ffuf.Result, 0)
	outp.fuzzkeywords = make([]string, 0)
	for _, ip := range conf.InputProviders {
		outp.fuzzkeywords = append(outp.fuzzkeywords, ip.Keyword)
	}
	sort.Strings(outp.fuzzkeywords)
	return &outp
}

func (s *Stdoutput) Banner() {
}

// Reset resets the result slice
func (s *Stdoutput) Reset() {
	s.CurrentResults = make([]ffuf.Result, 0)
}

// Cycle moves the CurrentResults to Results and resets the results slice
func (s *Stdoutput) Cycle() {
	s.Results = append(s.Results, s.CurrentResults...)
	s.Reset()
}

// GetResults returns the result slice
func (s *Stdoutput) GetCurrentResults() []ffuf.Result {
	return s.CurrentResults
}

// SetResults sets the result slice
func (s *Stdoutput) SetCurrentResults(results []ffuf.Result) {
	s.CurrentResults = results
}

func (s *Stdoutput) Progress(status ffuf.Progress) {
	// dur := time.Since(status.StartedAt)
	// runningSecs := int(dur / time.Second)
	// var reqRate int64
	// if runningSecs > 0 {
	// 	reqRate = status.ReqSec
	// } else {
	// 	reqRate = 0
	// }

	// hours := dur / time.Hour
	// dur -= hours * time.Hour
	// mins := dur / time.Minute
	// dur -= mins * time.Minute
	// secs := dur / time.Second

	// fmt.Fprintf(os.Stderr, "%s:: Progress: [%d/%d] :: Job [%d/%d] :: %d req/sec :: Duration: [%d:%02d:%02d] :: Errors: %d ::", TERMINAL_CLEAR_LINE, status.ReqCount, status.ReqTotal, status.QueuePos, status.QueueTotal, reqRate, hours, mins, secs, status.ErrorCount)
}

func (s *Stdoutput) Info(infostring string) {
	if s.config.Quiet {
		fmt.Fprintf(os.Stderr, "%s", infostring)
	} else {
		if !s.config.Colors {
			fmt.Fprintf(os.Stderr, "%s[INFO] %s\n\n", TERMINAL_CLEAR_LINE, infostring)
		} else {
			fmt.Fprintf(os.Stderr, "%s[%sINFO%s] %s\n\n", TERMINAL_CLEAR_LINE, ANSI_BLUE, ANSI_CLEAR, infostring)
		}
	}
}

func (s *Stdoutput) Error(errstring string) {
	if s.config.Quiet {
		fmt.Fprintf(os.Stderr, "%s", errstring)
	} else {
		if !s.config.Colors {
			fmt.Fprintf(os.Stderr, "%s[ERR] %s\n", TERMINAL_CLEAR_LINE, errstring)
		} else {
			fmt.Fprintf(os.Stderr, "%s[%sERR%s] %s\n", TERMINAL_CLEAR_LINE, ANSI_RED, ANSI_CLEAR, errstring)
		}
	}
}

func (s *Stdoutput) Warning(warnstring string) {
	if s.config.Quiet {
		fmt.Fprintf(os.Stderr, "%s", warnstring)
	} else {
		if !s.config.Colors {
			fmt.Fprintf(os.Stderr, "%s[WARN] %s\n", TERMINAL_CLEAR_LINE, warnstring)
		} else {
			fmt.Fprintf(os.Stderr, "%s[%sWARN%s] %s\n", TERMINAL_CLEAR_LINE, ANSI_RED, ANSI_CLEAR, warnstring)
		}
	}
}

func (s *Stdoutput) Raw(output string) {
	fmt.Fprintf(os.Stderr, "%s%s", TERMINAL_CLEAR_LINE, output)
}

// SaveFile saves the current results to a file of a given type
func (s *Stdoutput) SaveFile(filename, format string) error {
	var err error
	if s.config.OutputSkipEmptyFile && len(s.Results) == 0 {
		s.Info("No results and -or defined, output file not written.")
		return err
	}
	switch format {
	case "json":
		err = writeJSON(filename, s.config, append(s.Results, s.CurrentResults...))
	}
	return err
}

// Finalize gets run after all the ffuf jobs are completed
func (s *Stdoutput) Finalize() error {
	var err error
	if s.config.OutputFile != "" {
		err = s.SaveFile(s.config.OutputFile, s.config.OutputFormat)
		if err != nil {
			s.Error(err.Error())
		}
	}
	if !s.config.Quiet {
		fmt.Fprintf(os.Stderr, "\n")
	}
	return nil
}

func (s *Stdoutput) Result(resp ffuf.Response) {
	// Do we want to write request and response to a file
	if len(s.config.OutputDirectory) > 0 {
		resp.ResultFile = s.writeResultToFile(resp)
	}

	inputs := make(map[string][]byte, len(resp.Request.Input))
	for k, v := range resp.Request.Input {
		inputs[k] = v
	}
	sResult := ffuf.Result{
		Input:            inputs,
		Position:         resp.Request.Position,
		StatusCode:       resp.StatusCode,
		ContentLength:    resp.ContentLength,
		ContentWords:     resp.ContentWords,
		ContentLines:     resp.ContentLines,
		ContentType:      resp.ContentType,
		RedirectLocation: resp.GetRedirectLocation(false),
		ScraperData:      resp.ScraperData,
		Url:              resp.Request.Url,
		Duration:         resp.Time,
		ResultFile:       resp.ResultFile,
		Host:             resp.Request.Host,
	}
	s.CurrentResults = append(s.CurrentResults, sResult)
	// Output the result
	//s.PrintResult(sResult)
}

func (s *Stdoutput) writeResultToFile(resp ffuf.Response) string {
	var fileContent, fileName, filePath string
	// Create directory if needed
	if s.config.OutputDirectory != "" {
		err := os.MkdirAll(s.config.OutputDirectory, 0750)
		if err != nil {
			if !os.IsExist(err) {
				s.Error(err.Error())
				return ""
			}
		}
	}
	fileContent = fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", resp.Request.Raw, resp.Raw)

	// Create file name
	fileName = fmt.Sprintf("%x", md5.Sum([]byte(fileContent)))

	filePath = path.Join(s.config.OutputDirectory, fileName)
	err := os.WriteFile(filePath, []byte(fileContent), 0640)
	if err != nil {
		s.Error(err.Error())
	}
	return fileName
}

func (s *Stdoutput) PrintResult(res ffuf.Result) {
}
