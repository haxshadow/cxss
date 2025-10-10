## cxss
Special character reflection checker. Feeds URLs and reports which special characters reflect unfiltered.

### Features
- Detects reflected query parameters
- Tests special characters: " ' < > $ | ( ) ` : ; { }
- Fast concurrent pipeline
- Flexible input: single URL, file, or stdin
- Output to stdout or file
- Custom placeholder mode with `-p` flag for targeted testing
- Injection URL generation with `-i` flag when vulnerabilities are found

### Go (1.19+) recommended.

## Install

```bash
go install github.com/haxshadow/cxss@latest
```

Build from source:
```bash
git clone https://github.com/haxshadow/cxss.git
cd cxss
go build -o cxss .
```

### Options
```text
usage: cxss [-h] [-u URL] [-f FILE] [-o OUTPUT] -p PLACEHOLDER [-i INJECTION] [-t TIMEOUT] [-s]

Check which special characters reflect unfiltered in source code.

options:
  -h, --help            show this help message and exit
  -u, --url URL         Single URL with parameters (e.g,
                        http://site.com/page.php?id=1&cat=2)
  -f, --file FILE       File containing list of URLs (one per line, or '-' for stdin)
  -o, --output OUTPUT   Save results to file (plain text)
  -p, --placeholder     Custom placeholder text to find in URLs and use as injection point (REQUIRED)
  -i, --injection       Injection text to replace parameter values when special characters are found
  -s, --silent          Silent mode - hide banner

  -t, --timeout         TIMEOUT Request timeout in seconds (default: 10)
```

### Usage

- Single URL:
```bash
cxss -u "http://testasp.vulnweb.com/Search.asp?tfSearch=RXSS" -p "RXSS" -i "FUZZ" -o out.txt
```
### File should contain urls like:
```text
http://testphp.vulnweb.com/artists.php?artist=RXSS
http://testphp.vulnweb.com/listproducts.php?cat=RXSS
http://testphp.vulnweb.com/Mod_Rewrite_Shop/rate.php?id=RXSS
http://testhtml5.vulnweb.com/comment?id=RXSS
http://testasp.vulnweb.com/Login.asp?RetURL=RXSS
http://testasp.vulnweb.com/Register.asp?RetURL=RXSS
http://testasp.vulnweb.com/Search.asp?tfsearch=RXSS
http://testasp.vulnweb.com/search.asp?tfSearch=RXSS
```
- File input(-p flag value must be parameter value):
```bash
cxss -f rxss_urls.txt -p "RXSS" -i "FUZZ" -o out.txt
```
- Piping mode:
```bash
cat rxss_urls.txt | ./cxss -p "RXSS" -i "FUZZ" -o out.txt
```
- Piping mode 2:
```bash
echo "http://testasp.vulnweb.com/Search.asp?tfSearch=RXSS&two=ok" | cxss -p "RXSS" -i "FUZZ" -o out.txt
```
- Silent mode (no banner):
```bash
cxss -f rxss_urls.txt -p "RXSS" -i "FUZZ" -s -o out.txt
```


### Notes
- TLS verification is disabled for scanning convenience
- Redirects are not followed (3xx responses are skipped)
- Only `text/html` (or content types containing "html") are scanned

### Contributors:
<a href="https://github.com/h6nt3r">
  <img src="https://avatars.githubusercontent.com/u/196196358?v=4" alt="h6nt3r" style="width:50px; height:auto;border-radius:50%;">
</a>

### License
MIT (or your choice) – update this section accordingly.


