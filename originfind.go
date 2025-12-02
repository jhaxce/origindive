// originfind.go
//
// Origin IP Finder - Security Analysis Tool
// Author: jhaxce
// Purpose: Find origin servers behind WAF/CDN by checking IPs with custom Host header
// Build: go build -o originfind originfind.go
//
// Usage examples (after build):
//  ./originfind -d example.com -s 23.192.228.80 -e 23.192.228.90
//  ./originfind -d example.com -n 23.192.228.0/24 -j 10 -o results.txt
//  ./originfind -d example.com -i ips.txt -j 20 -a
//  ./originfind example.com 23.192.228.80 23.192.228.90
//
// Notes:
//  - Makes HTTP requests to http://<ip>/ with Host: <domain>
//  - Finds origin IPs behind Cloudflare, Akamai, and other CDN/WAF
//  - Supports IP ranges, CIDR notation, and input files
//  - Use responsibly against systems you are authorized to test.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const version = "2.4"

var (
	// CLI flags
	domain         = flag.String("d", "", "Target domain (e.g., example.com)")
	ipStart        = flag.String("s", "", "Start IP (e.g., 23.192.228.80)")
	ipEnd          = flag.String("e", "", "End IP (e.g., 23.192.228.90)")
	subnet         = flag.String("n", "", "CIDR subnet (e.g., 192.168.0.0/24)")
	inputFile      = flag.String("i", "", "Input file with IPs/CIDRs (one per line)")
	timeoutSec     = flag.Int("t", 5, "Request timeout seconds (overall)")
	connectTimeout = flag.Int("c", 3, "TCP connect timeout seconds")
	threads        = flag.Int("j", 1, "Number of parallel workers (recommended 1-20)")
	verbose        = flag.Bool("v", false, "Verbose output")
	quiet          = flag.Bool("q", false, "Quiet mode (minimal output)")
	showAll        = flag.Bool("a", false, "Show all responses (not just 200 OK)")
	saveOutput     = flag.String("o", "", "Save results to file")
	customHeader   = flag.String("H", "", "Add custom header (format: \"Name: value\")")
	httpMethod     = flag.String("m", "GET", "HTTP method (default: GET)")
	plain          = flag.Bool("p", false, "Plain text output (no colors)")
	noColorFlag    = flag.Bool("no-color", false, "Disable color output")
	showVersion    = flag.Bool("V", false, "Show version and exit")
	helpFlag       = flag.Bool("h", false, "Show help")
)

// Color helpers
var (
	RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, NC string
)

func initColors(enabled bool) {
	if !enabled {
		RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, NC = "", "", "", "", "", "", "", ""
		return
	}
	RED = "\u001b[0;31m"
	GREEN = "\u001b[0;32m"
	YELLOW = "\u001b[1;33m"
	BLUE = "\u001b[0;34m"
	CYAN = "\u001b[0;36m"
	MAGENTA = "\u001b[0;35m"
	BOLD = "\u001b[1m"
	NC = "\u001b[0m"
}

func usage() {
	fmt.Printf(`%s════════════════════════════════════════════════════════════════%s
              _       _       _____           __
  ____  _____(_)___ _(_)___  / __(_)___  ____/ /
 / __ \/ ___/ / __ `+"`"+` / / __ \/ /_/ / __ \/ __  / 
/ /_/ / /  / / /_/ / / / / / __/ / / / / /_/ /  
\____/_/  /_/\__, /_/_/ /_/_/ /_/_/ /_/\__,_/   
            /____/

%sOrigin IP Finder v%s - Security Tool%s
%sFind origin servers behind WAF/CDN (Cloudflare, Akamai, etc.)%s
%s════════════════════════════════════════════════════════════════%s

USAGE:
  # IP range:
  originfind -d <domain> -s <ip_start> -e <ip_end>
  originfind <domain> <ip_start> <ip_end>

  # CIDR subnet:
  originfind -d <domain> -n <CIDR>

  # Input file (IPs and/or CIDRs):
  originfind -d <domain> -i <file>

OPTIONS:
`, CYAN, NC, CYAN, version, NC, CYAN, NC, CYAN, NC)
	flag.PrintDefaults()
	fmt.Printf(`
EXAMPLES:
  # Simple IP range scan
  originfind example.com 23.192.228.80 23.192.228.90

  # CIDR with multiple threads (faster)
  originfind -d example.com -n 23.192.228.0/24 -j 10

  # Input file with mixed IPs/CIDRs
  originfind -d example.com -i ips.txt -j 20 -a -o results.txt

  # Show all responses (not just 200 OK)
  originfind -d example.com -n 192.168.1.0/24 -a -v

  # Plain text output (good for WSL/piping)
  originfind -d example.com -i targets.txt -p -j 15

CIDR REFERENCE:
  /32 = 1 IP       /28 = 16 IPs     /24 = 256 IPs
  /31 = 2 IPs      /27 = 32 IPs     /23 = 512 IPs
  /30 = 4 IPs      /26 = 64 IPs     /22 = 1024 IPs
  /29 = 8 IPs      /25 = 128 IPs    /21 = 2048 IPs

NOTES:
  • Finds real origin IPs behind CDN/WAF by testing Host header
  • Input file can contain mix of single IPs and CIDR ranges
  • Use -j flag for parallel scanning (recommended: 5-20 threads)
  • Be responsible - only scan systems you're authorized to test

`)
}

func isValidDomain(d string) bool {
	// Basic validation; avoids accepting strings with spaces or slashes
	if d == "" {
		return false
	}
	if strings.ContainsAny(d, " /\\:") {
		return false
	}
	// additional check: last char shouldn't be '-'
	if strings.HasPrefix(d, "-") || strings.HasSuffix(d, "-") {
		return false
	}
	return true
}

// parseInputFile reads IPs and CIDRs from file, returns list of IP ranges
func parseInputFile(filename string) ([][2]uint32, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges [][2]uint32
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a CIDR
		if strings.Contains(line, "/") {
			ip, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Printf("Warning: Invalid CIDR at line %d: %s (skipping)\n", lineNum, line)
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 {
				fmt.Printf("Warning: Only IPv4 supported at line %d (skipping)\n", lineNum)
				continue
			}
			network := ipToUint32(ip.Mask(ipNet.Mask))
			var first, last uint32
			if ones < 31 {
				first = network + 1
				last = ipToUint32(ipNet.IP) | ^ipToUint32(net.IP(ipNet.Mask))
				last = last - 1
			} else if ones == 31 {
				first = network
				last = network + 1
			} else { // /32
				first = network
				last = network
			}
			ranges = append(ranges, [2]uint32{first, last})
		} else {
			// Single IP
			ip := net.ParseIP(line)
			if ip == nil {
				fmt.Printf("Warning: Invalid IP at line %d: %s (skipping)\n", lineNum, line)
				continue
			}
			ipInt := ipToUint32(ip)
			if ipInt == 0 {
				fmt.Printf("Warning: Invalid IPv4 at line %d (skipping)\n", lineNum)
				continue
			}
			ranges = append(ranges, [2]uint32{ipInt, ipInt})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("no valid IPs or CIDRs found in file")
	}

	return ranges, nil
}

// ip <-> uint32 conversions
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

type result struct {
	Status   string // "200", "3xx", "000", "err", "xxx"
	IP       string
	HTTPCode int
	Err      error
}

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan uint32, results chan<- result, client *http.Client, domain string, header string, method string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ipInt, ok := <-jobs:
			if !ok {
				return
			}
			ip := uint32ToIP(ipInt).String()
			// Build request
			req, err := http.NewRequest(method, "http://"+ip+"/", nil)
			if err != nil {
				results <- result{Status: "err", IP: ip, Err: err}
				continue
			}
			// Set Host header to test origin behind CDN
			req.Host = domain
			req.Header.Set("User-Agent", "originip-go/1.0")
			if header != "" {
				parts := strings.SplitN(header, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				} else {
					// If custom header is invalid, still attach the raw value to a special header
					req.Header.Set("X-Custom-Header", header)
				}
			}

			// Execute request with context to allow cancellation
			resp, err := client.Do(req)
			if err != nil {
				// classify timeout vs other
				if os.IsTimeout(err) || strings.Contains(err.Error(), "Client.Timeout") || strings.Contains(err.Error(), "i/o timeout") {
					results <- result{Status: "000", IP: ip, Err: err}
				} else {
					results <- result{Status: "err", IP: ip, Err: err}
				}
				continue
			}
			// Do not follow redirects because transport's CheckRedirect returns ErrUseLastResponse in client below
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == 200 {
				results <- result{Status: "200", IP: ip, HTTPCode: code}
			} else if code >= 300 && code < 400 {
				results <- result{Status: "3xx", IP: ip, HTTPCode: code}
			} else {
				results <- result{Status: "xxx", IP: ip, HTTPCode: code}
			}
		}
	}
}

func main() {
	flag.Usage = usage
	flag.Parse()

	// Quick flags behavior
	if *helpFlag {
		usage()
		return
	}
	if *showVersion {
		fmt.Printf("Origin IP Finder %s\n", version)
		return
	}

	// support positional args: domain start end
	args := flag.Args()
	if len(args) >= 1 && *domain == "" {
		*domain = args[0]
	}
	if len(args) >= 3 && *ipStart == "" && *ipEnd == "" && *subnet == "" && *inputFile == "" {
		*ipStart = args[1]
		*ipEnd = args[2]
	}

	// init colors
	colorEnabled := true
	if *plain || *noColorFlag || (os.Getenv("NO_COLOR") == "1") {
		colorEnabled = false
	}
	initColors(colorEnabled)

	// Basic validation
	if *domain == "" {
		fmt.Println(RED + "Error: Domain is required (-d)" + NC)
		usage()
		os.Exit(1)
	}
	if !isValidDomain(*domain) {
		fmt.Printf("%sError: Invalid domain format: %s%s\n", RED, *domain, NC)
		os.Exit(1)
	}

	var ipRanges [][2]uint32
	var ipCount uint64

	// Determine input mode
	if *inputFile != "" {
		// File input mode
		if *subnet != "" || *ipStart != "" || *ipEnd != "" {
			fmt.Printf("%sError: Cannot use -i with -n, -s, or -e%s\n", RED, NC)
			os.Exit(1)
		}
		ranges, err := parseInputFile(*inputFile)
		if err != nil {
			fmt.Printf("%sError: Failed to read input file: %v%s\n", RED, err, NC)
			os.Exit(1)
		}
		ipRanges = ranges
		for _, r := range ipRanges {
			ipCount += uint64(r[1]-r[0]) + 1
		}
	} else if *subnet != "" {
		// parse CIDR
		ip, ipNet, err := net.ParseCIDR(*subnet)
		if err != nil {
			fmt.Printf("%sError: Invalid CIDR: %s%s\n", RED, *subnet, NC)
			os.Exit(1)
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 32 {
			fmt.Printf("%sError: Only IPv4 CIDR supported%s\n", RED, NC)
			os.Exit(1)
		}
		network := ipToUint32(ip.Mask(ipNet.Mask))
		// calculate range: skip network and broadcast for typical subnets (unless /31 or /32)
		var first, last uint32
		if ones < 31 {
			first = network + 1
			last = ipToUint32(ipNet.IP) | ^ipToUint32(net.IP(ipNet.Mask))
			last = last - 1
		} else if ones == 31 {
			// two usable IPs (no skipping)
			first = network
			last = network + 1
		} else { // /32
			first = network
			last = network
		}
		ipRanges = [][2]uint32{{first, last}}
		ipCount = uint64(last-first) + 1
	} else {
		// range mode: both start and end required
		if *ipStart == "" || *ipEnd == "" {
			fmt.Println(RED + "Error: Either use -i (file), -n (CIDR), or -s/-e (range)" + NC)
			usage()
			os.Exit(1)
		}
		startIP := net.ParseIP(*ipStart)
		endIPAddr := net.ParseIP(*ipEnd)
		if startIP == nil || endIPAddr == nil {
			fmt.Printf("%sError: Invalid IP format%s\n", RED, NC)
			os.Exit(1)
		}
		startInt := ipToUint32(startIP)
		endInt := ipToUint32(endIPAddr)
		if startInt > endInt {
			fmt.Printf("%sError: Start IP greater than End IP%s\n", RED, NC)
			os.Exit(1)
		}
		ipRanges = [][2]uint32{{startInt, endInt}}
		ipCount = uint64(endInt-startInt) + 1
	}

	if ipCount == 0 {
		fmt.Printf("%sError: No IPs to scan%s\n", RED, NC)
		os.Exit(1)
	}
	if ipCount > 65536 {
		// Warn and ask for confirmation
		fmt.Printf("%sWarning: Large IP range (%d IPs). This may take a long time.%s\n", YELLOW, ipCount, NC)
		fmt.Print("Continue? (y/n) ")
		var resp string
		fmt.Scanln(&resp)
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp)), "y") {
			fmt.Println("Scan cancelled")
			os.Exit(0)
		}
	}

	if *threads < 1 {
		*threads = 1
	}

	if *threads > 200 {
		fmt.Printf("%sWarning: Very large thread count (%d). This may be aggressive.%s\n", YELLOW, *threads, NC)
	}

	// Output header unless quiet
	if !*quiet {
		fmt.Println()
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Printf("Origin IP Finder %s\n", version)
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Printf("[*] Domain: %s\n", *domain)
		if *inputFile != "" {
			fmt.Printf("[*] Input File: %s\n", *inputFile)
			fmt.Printf("[*] IP Ranges: %d range(s)\n", len(ipRanges))
		} else if *subnet != "" {
			fmt.Printf("[*] CIDR Subnet: %s\n", *subnet)
			fmt.Printf("[*] IP Range: %s - %s\n", uint32ToIP(ipRanges[0][0]).String(), uint32ToIP(ipRanges[0][1]).String())
		} else {
			fmt.Printf("[*] IP Range: %s - %s\n", uint32ToIP(ipRanges[0][0]).String(), uint32ToIP(ipRanges[0][1]).String())
		}
		fmt.Printf("[*] Total IPs to check: %d\n", ipCount)
		fmt.Printf("[*] HTTP Method: %s\n", *httpMethod)
		fmt.Printf("[*] Timeout: %ds\n", *timeoutSec)
		fmt.Printf("[*] Connect Timeout: %ds\n", *connectTimeout)
		fmt.Printf("[*] Parallel Workers: %d\n", *threads)
		if *customHeader != "" {
			fmt.Printf("[*] Custom Header: %s\n", *customHeader)
		}
		if *plain {
			fmt.Printf("[*] Output Mode: Plain Text\n")
		} else if !colorEnabled {
			fmt.Printf("[*] Output Mode: No color\n")
		} else {
			fmt.Printf("[*] Output Mode: Colored\n")
		}
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println()
	}

	// Prepare results output file if requested
	var outFile *os.File
	var err error
	if *saveOutput != "" {
		outFile, err = os.Create(*saveOutput)
		if err != nil {
			fmt.Printf("%sError: Cannot create output file: %v%s\n", RED, err, NC)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	// Create HTTP client with custom transport and timeouts
	dialer := &net.Dialer{
		Timeout:   time.Duration(*connectTimeout) * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  true,
		// Skip TLS verify if someone points to HTTPS later; but we use http:// so not relevant.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(*timeoutSec) * time.Second,
		// Don't follow redirects - capture 3xx
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Prepare channels and workers
	jobs := make(chan uint32, *threads*2)
	results := make(chan result, *threads*2)
	ctx, _ := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, results, client, *domain, *customHeader, strings.ToUpper(*httpMethod))
	}

	// Launch result collector goroutine
	var totalScanned uint64
	var successCount uint64
	var redirectsCount uint64
	var otherCount uint64
	var timeoutCount uint64
	var errCount uint64

	var resultsLock sync.Mutex
	var printedLines []string

	collectorDone := make(chan struct{})
	go func() {
		for res := range results {
			atomic.AddUint64(&totalScanned, 1)
			line := ""
			switch res.Status {
			case "200":
				atomic.AddUint64(&successCount, 1)
				line = fmt.Sprintf("[+] %s --> 200 OK", res.IP)
			case "3xx":
				atomic.AddUint64(&redirectsCount, 1)
				if *showAll {
					line = fmt.Sprintf("[>] %s --> HTTP %d (Redirect)", res.IP, res.HTTPCode)
				}
			case "000":
				atomic.AddUint64(&timeoutCount, 1)
				if *showAll {
					line = fmt.Sprintf("[~] %s --> No Response/Timeout (%v)", res.IP, res.Err)
				}
			case "xxx":
				atomic.AddUint64(&otherCount, 1)
				if *showAll {
					line = fmt.Sprintf("[~] %s --> HTTP %d", res.IP, res.HTTPCode)
				}
			case "err":
				atomic.AddUint64(&errCount, 1)
				if *showAll {
					line = fmt.Sprintf("[-] %s --> Error: %v", res.IP, res.Err)
				}
			default:
				// unknown
				if *showAll {
					line = fmt.Sprintf("[?] %s --> %v", res.IP, res.Err)
				}
			}

			// Output line if not quiet and line is non-empty (either success or showAll)
			if line != "" && !*quiet {
				fmt.Println(line)
			}
			// Save to output file (cleaner format like bash script)
			if outFile != nil && line != "" {
				// Strip color codes for file output
				cleanLine := line
				for _, color := range []string{RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, NC} {
					cleanLine = strings.ReplaceAll(cleanLine, color, "")
				}
				fmt.Fprintln(outFile, cleanLine)
			}

			// keep printed lines in memory for potential later use (not required)
			if line != "" {
				resultsLock.Lock()
				printedLines = append(printedLines, line)
				resultsLock.Unlock()
			}
		}
		close(collectorDone)
	}()

	// Feed jobs from all IP ranges
	startTime := time.Now()
	go func() {
		for _, r := range ipRanges {
			for ip := r[0]; ip <= r[1]; ip++ {
				jobs <- ip
			}
		}
		close(jobs)
	}()

	// Wait for workers to finish
	wg.Wait()
	// All workers done, close results channel and wait for collector
	close(results)
	<-collectorDone
	endTime := time.Now()
	elapsed := endTime.Sub(startTime).Seconds()

	// Summary output
	if !*quiet {
		fmt.Println()
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println("Scan Results Summary")
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Printf("[+] 200 OK Found: %d\n", atomic.LoadUint64(&successCount))
		fmt.Printf("[>] Redirects (3xx): %d\n", atomic.LoadUint64(&redirectsCount))
		fmt.Printf("[~] Other Responses: %d\n", atomic.LoadUint64(&otherCount))
		fmt.Printf("[-] Timeout/Error: %d\n", atomic.LoadUint64(&timeoutCount)+atomic.LoadUint64(&errCount))
		fmt.Printf("[*] Total Scanned: %d\n", atomic.LoadUint64(&totalScanned))
		fmt.Printf("[T] Elapsed Time: %.2fs\n", elapsed)
		if elapsed > 0 {
			rate := float64(atomic.LoadUint64(&totalScanned)) / elapsed
			fmt.Printf("[S] Scan Rate: %.2f IPs/sec (%d worker(s))\n", rate, *threads)
		}
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println()
	}

	// Close output file if any
	if outFile != nil {
		fmt.Printf("[*] Results saved to: %s\n", *saveOutput)
	}

	// set exit code
	if atomic.LoadUint64(&successCount) > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
