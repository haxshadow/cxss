package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type paramCheck struct {
	URL   string
	Param string
	Idx   int
	Total int
}

type URLResult struct {
	Idx            int
	Lines          []string // full formatted lines (with prefix) for stdout
	LinesForFile   []string // kept for compatibility
	UnfilteredAdd  int64
	TimeoutsAdd    int64
	ErrorsAdd      int64
}

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

var httpClient = &http.Client{
	Transport: transport,
}

var (
	totalUnfiltered int64
	totalTimeouts   int64
	totalErrors     int64
)

func printBanner() {
	banner := `
    #        Special Characters Reflection Checker V-3.0.1        #
    #        Developed by @haxshadow             #
    #        Contributor @h6nt3r          # 

[!] legal disclaimer: Usage of cxss for attacking targets without prior mutual consent is illegal. 
    It is the end user's responsibility to obey all applicable local, state and federal laws. 
    Developers assume no liability and are not responsible for any misuse or damage caused by this program.

`
	fmt.Print(banner)
}

func main() {
	// Flags
	flag.Usage = func() {
		printBanner()
		usage := "usage: cxss [-h] [-u URL] [-f FILE] [-p PLACEHOLDER] [-i INJECTION] [-t TIMEOUT] [-c THREADS] [-s] [-o OUTPUT]\n\n" +
			"Special Character Reflection Checker.\n\n" +
			"options:\n" +
			"  -h                   Show this help message and exit\n" +
			"  -u, --url URL        Single URL with parameters\n" +
			"  -f, --file FILE      File containing list of URLs (one per line)\n" +
			"  -p, --placeholder    Custom placeholder text to find in URLs and use as injection point (REQUIRED)\n" +
			"  -i, --injection      Injection text to replace parameter values when special characters are found\n" +
			"  -t, --timeout        Request timeout in seconds (default: 10)\n" +
			"  -c, --threads        Number of concurrent threads (default: 5)\n" +
			"  -s, --silent         Silent mode - hide banner\n" +
			"  -o, --output         Save results to file (plain text)\n\n"
		fmt.Fprint(os.Stderr, usage)
	}

	var (
		flagURL         string
		flagFile        string
		flagPlaceholder string
		flagInjection   string
		flagTimeout     int
		flagThreads     int
		flagSilent      bool
		flagOutput      string
	)

	flag.StringVar(&flagURL, "u", "", "Single URL with parameters")
	flag.StringVar(&flagURL, "url", "", "Single URL with parameters")
	flag.StringVar(&flagFile, "f", "", "File containing list of URLs (one per line)")
	flag.StringVar(&flagFile, "file", "", "File containing list of URLs (one per line)")
	flag.StringVar(&flagPlaceholder, "p", "", "Custom placeholder text to find in URLs and use as injection point (REQUIRED)")
	flag.StringVar(&flagPlaceholder, "placeholder", "", "Custom placeholder text to find in URLs and use as injection point (REQUIRED)")
	flag.StringVar(&flagInjection, "i", "", "Injection text to replace parameter values when special characters are found")
	flag.StringVar(&flagInjection, "injection", "", "Injection text to replace parameter values when special characters are found")
	flag.IntVar(&flagTimeout, "t", 10, "Request timeout in seconds (default: 10)")
	flag.IntVar(&flagTimeout, "timeout", 10, "Request timeout in seconds (default: 10)")
	flag.IntVar(&flagThreads, "c", 5, "Number of concurrent threads (default: 5)")
	flag.IntVar(&flagThreads, "threads", 5, "Number of concurrent threads (default: 5)")
	flag.BoolVar(&flagSilent, "s", false, "Silent mode - hide banner")
	flag.BoolVar(&flagSilent, "silent", false, "Silent mode - hide banner")
	flag.StringVar(&flagOutput, "o", "", "Save results to file (plain text)")
	flag.StringVar(&flagOutput, "output", "", "Save results to file (plain text)")

	flag.Parse()

	// -p required
	if flagPlaceholder == "" {
		if !flagSilent {
			printBanner()
		}
		fmt.Fprintln(os.Stderr, "Error: -p flag is required. Please specify a placeholder text.")
		os.Exit(1)
	}

	if !flagSilent {
		printBanner()
	}

	// apply timeout to httpClient
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	httpClient.Timeout = time.Duration(flagTimeout) * time.Second

	// prepare output file (open once, append as results come)
	var fileWriter *os.File
	var fileMu sync.Mutex
	if flagOutput != "" {
		dir := filepath.Dir(flagOutput)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fmt.Fprintf(os.Stderr, "failed to create output directory: %s\n", err)
				os.Exit(1)
			}
		}
		// create/truncate then use for appending while running
		f, err := os.Create(flagOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create output file: %s\n", err)
			os.Exit(1)
		}
		fileWriter = f
		defer fileWriter.Close()
	}

	// collect URLs
	urls := make([]string, 0)
	if flagURL != "" {
		urls = append(urls, flagURL)
	}
	if flagFile != "" {
		if flagFile == "-" {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line != "" {
					urls = append(urls, line)
				}
			}
			if err := sc.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "failed reading stdin: %s\n", err)
				os.Exit(1)
			}
		} else {
			file, err := os.Open(flagFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open file: %s\n", err)
				os.Exit(1)
			}
			defer file.Close()
			sc := bufio.NewScanner(file)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line != "" {
					urls = append(urls, line)
				}
			}
			if err := sc.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "failed reading file: %s\n", err)
				os.Exit(1)
			}
		}
	}

	// fallback stdin
	if len(urls) == 0 {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line != "" {
					urls = append(urls, line)
				}
			}
			if err := sc.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "failed reading stdin: %s\n", err)
				os.Exit(1)
			}
		}
	}

	if len(urls) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// clamp threads
	if flagThreads < 1 {
		flagThreads = 1
	}
	if flagThreads > 50 {
		flagThreads = 50
	}

	total := len(urls)
	startTime := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, flagThreads)
	// mutex to keep stdout/file writes atomic per-result
	var printMu sync.Mutex

	// launch workers
	for i, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, target string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := scanSingleURL(idx+1, total, target, flagPlaceholder, flagInjection)

			// aggregate counters atomically
			if res.UnfilteredAdd != 0 {
				atomic.AddInt64(&totalUnfiltered, res.UnfilteredAdd)
			}
			if res.TimeoutsAdd != 0 {
				atomic.AddInt64(&totalTimeouts, res.TimeoutsAdd)
			}
			if res.ErrorsAdd != 0 {
				atomic.AddInt64(&totalErrors, res.ErrorsAdd)
			}

			// print & write immediately (synchronized)
			printMu.Lock()
			for _, line := range res.Lines {
				fmt.Fprintln(os.Stdout, line)
				if fileWriter != nil {
					// safe write to file
					fileMu.Lock()
					_, _ = io.WriteString(fileWriter, line+"\n")
					fileMu.Unlock()
				}
			}
			printMu.Unlock()
		}(i, u)
	}

	// wait for all workers
	wg.Wait()

	// final summary
	if !flagSilent {
		elapsed := time.Since(startTime)
		minutes := int(elapsed.Seconds()) / 60
		seconds := int(elapsed.Seconds()) % 60

		fmt.Fprintln(os.Stdout)
		fmt.Fprintf(os.Stdout, "Total Unfiltered Urls: %d\n", atomic.LoadInt64(&totalUnfiltered))
		fmt.Fprintf(os.Stdout, "Total Timeouts: %d\n", atomic.LoadInt64(&totalTimeouts))
		fmt.Fprintf(os.Stdout, "Total Errors: %d\n", atomic.LoadInt64(&totalErrors))
		fmt.Fprintf(os.Stdout, "Time taken: %d Minute %d Second\n", minutes, seconds)
	}
}

// scanSingleURL performs the full scanning for a single URL and returns URLResult.
func scanSingleURL(idx, total int, targetURL, placeholder, injection string) URLResult {
	out := URLResult{Idx: idx, Lines: []string{}, LinesForFile: []string{}}
	var localUnfiltered int64
	var localTimeouts int64
	var localErrors int64

	u, err := url.Parse(targetURL)
	if err != nil {
		localErrors++
		out.ErrorsAdd = localErrors
		return out
	}

	paramsToCheck := make([]string, 0)
	if placeholder != "" {
		qs := u.Query()
		for key, vv := range qs {
			for _, v := range vv {
				if v == placeholder {
					paramsToCheck = append(paramsToCheck, key)
					break
				}
			}
		}
	} else {
		reflected, err := checkReflected(targetURL)
		if err != nil {
			_ = err
		}
		if len(reflected) > 0 {
			paramsToCheck = append(paramsToCheck, reflected...)
		}
	}

	if len(paramsToCheck) == 0 {
		out.UnfilteredAdd = 0
		out.TimeoutsAdd = localTimeouts
		out.ErrorsAdd = localErrors
		return out
	}

	chars := []string{`"`, `'`, `<`, `>`, `$`, `|`, `(`, `)`, "`", ":", ";", "{", "}"}

	for _, param := range paramsToCheck {
		ok, err := checkAppend(targetURL, param, "iy3j4h234hjb23234")
		if err != nil {
			if netErr, okt := err.(net.Error); okt && netErr.Timeout() {
				localTimeouts++
			} else {
				localErrors++
			}
			continue
		}
		if !ok {
			continue
		}

		foundChars := make([]string, 0)
		for _, ch := range chars {
			ref, err := checkAppend(targetURL, param, "aprefix"+ch+"asuffix")
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					localTimeouts++
					continue
				}
				localErrors++
				continue
			}
			if ref {
				foundChars = append(foundChars, ch)
			}
		}

		if len(foundChars) > 0 {
			prefix := fmt.Sprintf("URL(%d/%d): ", idx, total)
			var printedTarget string
			if injection != "" {
				printedTarget = replaceParamValue(targetURL, param, injection)
			} else {
				printedTarget = targetURL
			}
			fullLine := fmt.Sprintf("%s%s Param: %s Unfiltered(%d): %v", prefix, printedTarget, param, len(foundChars), foundChars)
			out.Lines = append(out.Lines, fullLine)

			simpleLine := fmt.Sprintf("%s Param: %s Unfiltered(%d): %v", printedTarget, param, len(foundChars), foundChars)
			out.LinesForFile = append(out.LinesForFile, simpleLine)

			if len(foundChars) >= 1 && len(foundChars) <= 15 {
				localUnfiltered++
			}
		}
	}

	out.UnfilteredAdd = localUnfiltered
	out.TimeoutsAdd = localTimeouts
	out.ErrorsAdd = localErrors
	return out
}

// checkReflected: GET request to targetURL and returns list of params whose values appear in body
func checkReflected(targetURL string) ([]string, error) {
	out := make([]string, 0)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		atomic.AddInt64(&totalErrors, 1)
		return out, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")

	resp, err := httpClient.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			atomic.AddInt64(&totalTimeouts, 1)
			return out, nil
		}
		atomic.AddInt64(&totalErrors, 1)
		return out, err
	}
	if resp.Body == nil {
		return out, nil
	}
	defer resp.Body.Close()

	// skip redirects (3xx)
	if strings.HasPrefix(resp.Status, "3") {
		return out, nil
	}

	// skip non-html
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") {
		return out, nil
	}

	// read body (no huge-limit change here; can be adjusted if needed)
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		atomic.AddInt64(&totalErrors, 1)
		return out, err
	}
	body := string(b)

	u, err := url.Parse(targetURL)
	if err != nil {
		atomic.AddInt64(&totalErrors, 1)
		return out, err
	}

	for key, vv := range u.Query() {
		for _, v := range vv {
			if v == "" {
				continue
			}
			if strings.Contains(body, v) {
				out = append(out, key)
			}
		}
	}

	return out, nil
}

// checkAppend: append suffix to param value and check reflection (returns true if param reflected)
func checkAppend(targetURL, param, suffix string) (bool, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		atomic.AddInt64(&totalErrors, 1)
		return false, err
	}

	qs := u.Query()
	val := qs.Get(param)
	qs.Set(param, val+suffix)
	u.RawQuery = qs.Encode()

	reflected, err := checkReflected(u.String())
	if err != nil {
		return false, err
	}

	for _, r := range reflected {
		if r == param {
			return true, nil
		}
	}
	return false, nil
}

func replaceParamValue(targetURL, param, newValue string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	qs := u.Query()
	qs.Set(param, newValue)
	u.RawQuery = qs.Encode()
	return u.String()
}
