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
	"strings"
	"sync"
	"time"
)

type paramCheck struct {
	url   string
	param string
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

func main() {
	// CLI flags
	var (
		flagURL     string
		flagFile    string
		flagOutput  string
		flagTimeout int
		flagCustom  bool
	)

	flag.IntVar(&flagTimeout, "t", 10, "Request timeout in seconds (default: 10)")
	flag.IntVar(&flagTimeout, "timeout", 10, "Request timeout in seconds (default: 10)")
	flag.StringVar(&flagURL, "u", "", "Single URL with parameters (e.g., http://site.com/page.php?id=1&cat=2)")
	flag.StringVar(&flagURL, "url", "", "Single URL with parameters (e.g., http://site.com/page.php?id=1&cat=2)")
	flag.StringVar(&flagFile, "f", "", "File containing list of URLs (one per line)")
	flag.StringVar(&flagFile, "file", "", "File containing list of URLs (one per line)")
	flag.StringVar(&flagOutput, "o", "", "Save results to file (plain text)")
	flag.StringVar(&flagOutput, "output", "", "Save results to file (plain text)")
	flag.BoolVar(&flagCustom, "cp", false, "Enable pinpoint testing using 'FUZZ' marker in URLs. Only params with value 'FUZZ' are tested.")
	flag.BoolVar(&flagCustom, "custom-params", false, "Enable pinpoint testing using 'FUZZ' marker in URLs. Only params with value 'FUZZ' are tested.")

	flag.Usage = func() {
		usage := "usage: cxss [-h] [-u URL] [-f FILE] [-o OUTPUT] [-cp] [-t TIMEOUT]\n\n" +
			"Check which special characters reflect unfiltered in source code.\n\n" +
			"options:\n" +
			"  -h, --help            show this help message and exit\n" +
			"  -u, --url URL         Single URL with parameters (e.g,\n" +
			"                        http://site.com/page.php?id=1&cat=2)\n" +
			"  -f, --file FILE       File containing list of URLs (one per line, or '-' for stdin)\n" +
			"  -o, --output OUTPUT   Save results to file (plain text)\n" +
			"  -cp, --custom-params  Enable pinpoint testing using 'FUZZ' marker in URLs.\n" +
			"                        Works with all input methods (URL, file, stdin)\n" +
			"  -t, --timeout TIMEOUT Request timeout in seconds (default: 10)\n\n" +
			"examples:\n" +
			"  cxss -f urls.txt -cp -o output.txt\n" +
			"  cat urls.txt | cxss -t 50 -cp -o output.txt\n" +
			"  cxss -u 'http://site.com/?name=FUZZ&age=20' -cp\n"
		fmt.Fprint(os.Stderr, usage)
	}

	flag.Parse()

	// HTTP client behavior
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// Overall request timeout
	httpClient.Timeout = time.Duration(flagTimeout) * time.Second

	// Prepare output writer
	var outputWriter io.Writer = os.Stdout
	var outputFile *os.File
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create output file: %s\n", err)
			os.Exit(1)
		}
		outputFile = f
		defer outputFile.Close()
		outputWriter = outputFile
	}

	// Collect input URLs
	urls := make([]string, 0)
	if flagURL != "" {
		urls = append(urls, flagURL)
	}
	if flagFile != "" {
		if flagFile == "-" {
			// read from stdin explicitly
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				urls = append(urls, line)
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
				if line == "" {
					continue
				}
				urls = append(urls, line)
			}
			if err := sc.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "failed reading file: %s\n", err)
				os.Exit(1)
			}
		}
	}

	// fallback: if nothing specified, read from stdin
	if len(urls) == 0 {
		// Check if stdin has data available
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// stdin has data (piped input)
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				urls = append(urls, line)
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

	initialChecks := make(chan paramCheck, 40)

	appendChecks := makePool(initialChecks, func(c paramCheck, output chan paramCheck) {
		if flagCustom {
			u, err := url.Parse(c.url)
			if err != nil {
				return
			}
			qs := u.Query()
			for key, vv := range qs {
				for _, v := range vv {
					if v == "FUZZ" {
						output <- paramCheck{c.url, key}
						break
					}
				}
			}
			return
		}

		reflected, err := checkReflected(c.url)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "error from checkReflected: %s\n", err)
			return
		}

		if len(reflected) == 0 {
			// TODO: wrap in verbose mode
			//fmt.Printf("no params were reflected in %s\n", c.url)
			return
		}

		for _, param := range reflected {
			output <- paramCheck{c.url, param}
		}
	})

	charChecks := makePool(appendChecks, func(c paramCheck, output chan paramCheck) {
		wasReflected, err := checkAppend(c.url, c.param, "iy3j4h234hjb23234")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error from checkAppend for url %s with param %s: %s", c.url, c.param, err)
			return
		}

		if wasReflected {
			output <- paramCheck{c.url, c.param}
		}
	})

	done := makePool(charChecks, func(c paramCheck, output chan paramCheck) {
		output_of_url := []string{c.url, c.param}
		for _, char := range []string{"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}"} {
			wasReflected, err := checkAppend(c.url, c.param, "aprefix"+char+"asuffix")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error from checkAppend for url %s with param %s with %s: %s", c.url, c.param, char, err)
				continue
			}

			if wasReflected {
				output_of_url = append(output_of_url, char)
			}
		}
		if len(output_of_url) >= 2 {
			fmt.Fprintf(outputWriter, "URL: %s Param: %s Unfiltered: %v \n", output_of_url[0], output_of_url[1], output_of_url[2:])
		}
	})

	for _, u := range urls {
		initialChecks <- paramCheck{url: u}
	}

	close(initialChecks)
	<-done
}

func checkReflected(targetURL string) ([]string, error) {

	out := make([]string, 0)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return out, err
	}

	// temporary. Needs to be an option
	req.Header.Add("User-Agent", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return out, err
	}
	if resp.Body == nil {
		return out, err
	}
	defer resp.Body.Close()

	// always read the full body so we can re-use the tcp connection
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}

	// nope (:
	if strings.HasPrefix(resp.Status, "3") {
		return out, nil
	}

	// also nope
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") {
		return out, nil
	}

	body := string(b)

	u, err := url.Parse(targetURL)
	if err != nil {
		return out, err
	}

	for key, vv := range u.Query() {
		for _, v := range vv {
			if !strings.Contains(body, v) {
				continue
			}

			out = append(out, key)
		}
	}

	return out, nil
}

func checkAppend(targetURL, param, suffix string) (bool, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false, err
	}

	qs := u.Query()
	val := qs.Get(param)
	//if val == "" {
	//return false, nil
	//return false, fmt.Errorf("can't append to non-existant param %s", param)
	//}

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

type workerFunc func(paramCheck, chan paramCheck)

func makePool(input chan paramCheck, fn workerFunc) chan paramCheck {
	var wg sync.WaitGroup

	output := make(chan paramCheck)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			for c := range input {
				fn(c, output)
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(output)
	}()

	return output
}
