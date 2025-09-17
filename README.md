## cxss

Reflected XSS parameter and character reflection tester. Feeds URLs and reports which special characters reflect unfiltered.

### Features
- Detects reflected query parameters
- Tests special characters: " ' < > $ | ( ) ` : ; { }
- Fast concurrent pipeline
- Flexible input: single URL, file, or stdin
- Output to stdout or file
- Optional pinpoint mode with `FUZZ` marker

### Install

Go (1.19+) recommended.

From GitHub (after you publish the repo as `github.com/haxshadow/cxss`):
```bash
go install github.com/haxshadow/cxss@latest
```

Build from source:
```bash
git clone https://github.com/haxshadow/cxss.git
cd cxss
go build -o cxss .
```

### Usage
```text
usage: cxss [-h] [-u URL] [-f FILE] [-o OUTPUT] [-cp] [-t TIMEOUT]

Check which special characters reflect unfiltered in source code.

options:
  -h, --help            show this help message and exit
  -u, --url URL         Single URL with parameters (e.g,
                        http://site.com/page.php?id=1&cat=2)
  -f, --file FILE       File containing list of URLs (one per line, or '-' for stdin)
  -o, --output OUTPUT   Save results to file (plain text)
  -cp, --custom-params  Enable pinpoint testing using 'FUZZ' marker in URLs. Only params with value 'FUZZ' are tested.

  -t, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
```

### Examples

- Single URL:
```bash
cxss -u 'http://127.0.0.1:5566/?name=Alice&age=20' -t 10
```

- File input:
```bash
cxss -f urls.txt -o result.txt -t 10
```

- Stdin (explicit with `-f -`):
```bash
cat urls.txt | cxss -f - -o out.txt
```

- Stdin (no flags):
```bash
printf '%s\n' 'http://example/?q=hello' | cxss
```

- Pinpoint only params marked with `FUZZ`:
```bash
cxss -u 'http://127.0.0.1:5566/?name=FUZZ&age=20' -cp
```

- File input with custom params and output:
```bash
cxss -f urls.txt -cp -o output.txt
```

- Stdin with custom params, timeout and output:
```bash
cat urls.txt | cxss -t 50 -cp -o output.txt
```

### Local test server
Run a simple HTML echo server for quick testing:
```bash
go run ./cmd/testserver
# then in another shell
cxss -u 'http://127.0.0.1:5566/?name=Alice&age=20'
```

### Output format
```
URL: <url> Param: <param> Unfiltered: [<chars...>]
```

### Notes
- TLS verification is disabled for scanning convenience
- Redirects are not followed (3xx responses are skipped)
- Only `text/html` (or content types containing "html") are scanned

### License
MIT (or your choice) – update this section accordingly.


