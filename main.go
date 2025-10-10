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

func printBanner() {
	banner := `
    #        Special Characters Reflection Checker V-3.0.0        #
    #        Developed by @haxshadow             #
    #        Contributor @h6nt3r          # 

[!] legal disclaimer: Usage of cxss for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

`
	fmt.Print(banner)
}

func main() {
	// CLI flags
	var (
		flagURL        string
		flagFile       string
		flagOutput     string
		flagTimeout    int
		flagPlaceholder string
		flagInjection  string
		flagSilent     bool
	)

	flag.IntVar(&flagTimeout, "t", 10, "Request timeout in seconds (default: 10)")
	flag.IntVar(&flagTimeout, "timeout", 10, "Request timeout in seconds (default: 10)")
	flag.StringVar(&flagURL, "u", "", "Single URL with parameters (e.g., http://site.com/page.php?id=1&cat=2)")
	flag.StringVar(&flagURL, "url", "", "Single URL with parameters (e.g., http://site.com/page.php?id=1&cat=2)")
	flag.StringVar(&flagFile, "f", "", "File containing list of URLs (one per line)")
	flag.StringVar(&flagFile, "file", "", "File containing list of URLs (one per line)")
	flag.StringVar(&flagOutput, "o", "", "Save results to file (plain text)")
	flag.StringVar(&flagOutput, "output", "", "Save results to file (plain text)")
	flag.StringVar(&flagPlaceholder, "p", "", "Custom placeholder text to find in URLs and use as injection point")
	flag.StringVar(&flagPlaceholder, "placeholder", "", "Custom placeholder text to find in URLs and use as injection point")
	flag.StringVar(&flagInjection, "i", "", "Injection text to replace parameter values when special characters are found")
	flag.StringVar(&flagInjection, "injection", "", "Injection text to replace parameter values when special characters are found")
	flag.BoolVar(&flagSilent, "s", false, "Silent mode - hide banner")
	flag.BoolVar(&flagSilent, "silent", false, "Silent mode - hide banner")

	flag.Usage = func() {
		printBanner()
		usage := "usage: cxss [-h] [-u URL] [-f FILE] [-o OUTPUT] -p PLACEHOLDER [-i INJECTION] [-t TIMEOUT] [-s]\n\n" +
			"Check which special characters reflect unfiltered in source code.\n\n" +
			"options:\n" +
			"  -h, --help            show this help message and exit\n" +
			"  -u, --url URL         Single URL with parameters (e.g,\n" +
			"                        http://site.com/page.php?id=1&cat=2)\n" +
			"  -f, --file FILE       File containing list of URLs (one per line, or '-' for stdin)\n" +
			"  -o, --output OUTPUT   Save results to file (plain text)\n" +
			"  -p, --placeholder     Custom placeholder text to find in URLs and use as injection point (REQUIRED)\n" +
			"                        Works with all input methods (URL, file, stdin)\n" +
			"  -i, --injection       Injection text to replace parameter values when special characters are found\n" +
			"                        Works with all input methods (URL, file, stdin)\n" +
			"  -t, --timeout TIMEOUT Request timeout in seconds (default: 10)\n" +
			"  -s, --silent          Silent mode - hide banner\n\n" +
			"examples:\n" +
			"  cxss -f urls.txt -p X -i 'alert(1)' -o output.txt\n" +
			"  cat urls.txt | cxss -t 50 -p X -i 'XSS' -o output.txt\n" +
			"  cxss -u 'http://site.com/?name=X&age=20' -p X -i 'test'\n" +
			"  cxss -u 'http://site.com/?test=1' -s\n"
		fmt.Fprint(os.Stderr, usage)
	}

	flag.Parse()

	// Check if -p flag is provided (required)
	if flagPlaceholder == "" {
		if !flagSilent {
			printBanner()
		}
		fmt.Fprintf(os.Stderr, "Error: -p flag is required. Please specify a placeholder text.\n")
		fmt.Fprintf(os.Stderr, "Example: cxss -u 'http://site.com/?name=X' -p X\n")
		os.Exit(1)
	}

	// Print banner for any command execution (unless silent mode is enabled)
	if !flagSilent {
		printBanner()
	}

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
		// Write to both terminal and file
		outputWriter = io.MultiWriter(os.Stdout, outputFile)
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
		if flagPlaceholder != "" {
			u, err := url.Parse(c.url)
			if err != nil {
				return
			}
			qs := u.Query()
			for key, vv := range qs {
				for _, v := range vv {
					if v == flagPlaceholder {
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
			// Check if it's a timeout error and silently skip
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return // Silently skip timeout errors
			}
			fmt.Fprintf(os.Stderr, "error from checkAppend for url %s with param %s: %s", c.url, c.param, err)
			return
		}

		if wasReflected {
			output <- paramCheck{c.url, c.param}
		}
	})

	done := makePool(charChecks, func(c paramCheck, output chan paramCheck) {
		output_of_url := []string{c.url, c.param}
		hasUnfilteredChars := false
		
		for _, char := range []string{"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}"} {
			wasReflected, err := checkAppend(c.url, c.param, "aprefix"+char+"asuffix")
			if err != nil {
				// Check if it's a timeout error and silently skip
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Silently skip timeout errors
				}
				fmt.Fprintf(os.Stderr, "error from checkAppend for url %s with param %s with %s: %s", c.url, c.param, char, err)
				continue
			}

			if wasReflected {
				output_of_url = append(output_of_url, char)
				hasUnfilteredChars = true
			}
		}
		
		if len(output_of_url) >= 2 {
			unfilteredChars := output_of_url[2:]
			count := len(unfilteredChars)
			
			// If injection flag is provided and there are unfiltered characters, show injection URL as the main URL
			if flagInjection != "" && hasUnfilteredChars {
				injectionURL := replaceParamValue(c.url, c.param, flagInjection)
				fmt.Fprintf(outputWriter, "URL: %s Param: %s Unfiltered(%d): %v \n", 
					injectionURL, output_of_url[1], count, unfilteredChars)
			} else {
				fmt.Fprintf(outputWriter, "URL: %s Param: %s Unfiltered(%d): %v \n", 
					output_of_url[0], output_of_url[1], count, unfilteredChars)
			}
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
		// Check if it's a timeout error and silently skip
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return out, nil // Silently skip timeout errors
		}
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
		// Check if it's a timeout error and silently skip
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, nil // Silently skip timeout errors
		}
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
