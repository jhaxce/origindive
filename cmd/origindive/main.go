// origindive - Security analysis tool for origin IP discovery
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"

	"github.com/jhaxce/origindive/internal/colors"
	"github.com/jhaxce/origindive/internal/version"
	"github.com/jhaxce/origindive/pkg/asn"
	"github.com/jhaxce/origindive/pkg/core"
	"github.com/jhaxce/origindive/pkg/ip"
	"github.com/jhaxce/origindive/pkg/output"
	"github.com/jhaxce/origindive/pkg/passive/censys"
	"github.com/jhaxce/origindive/pkg/passive/ct"
	passivedns "github.com/jhaxce/origindive/pkg/passive/dns"
	"github.com/jhaxce/origindive/pkg/passive/dnsdumpster"
	"github.com/jhaxce/origindive/pkg/passive/securitytrails"
	"github.com/jhaxce/origindive/pkg/passive/shodan"
	"github.com/jhaxce/origindive/pkg/passive/subdomain"
	"github.com/jhaxce/origindive/pkg/passive/viewdns"
	"github.com/jhaxce/origindive/pkg/passive/virustotal"
	"github.com/jhaxce/origindive/pkg/passive/wayback"
	"github.com/jhaxce/origindive/pkg/passive/zoomeye"
	"github.com/jhaxce/origindive/pkg/scanner"
	"github.com/jhaxce/origindive/pkg/update"
	"github.com/jhaxce/origindive/pkg/waf"
)

func main() {
	// Check for updates first (non-blocking notification)
	go checkForUpdatesAsync()

	// Initialize global config on first run
	autoInitializeGlobalConfig()

	// Parse command line flags
	config, outputFlagProvided := parseFlags()

	// Initialize colors
	colors.Init(!config.NoColor)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "%sError: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}

	// Set WAF database path (user cache or repo default)
	config.WAFDatabasePath = getWAFDatabasePath()

	// Print banner once at the start
	if !config.Quiet {
		printBanner(config)
	}

	// Handle passive and auto modes
	var passiveIPs []string
	if config.Mode == core.ModePassive || config.Mode == core.ModeAuto {
		// Run passive reconnaissance
		if !config.Quiet {
			fmt.Printf("\n%s═══════════════════════════════════════════════════════════════%s\n", colors.CYAN, colors.NC)
			fmt.Printf("%s  Starting Passive Reconnaissance%s\n", colors.BOLD, colors.NC)
			fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n", colors.CYAN, colors.NC)
		}

		var err error
		passiveIPs, err = runPassiveRecon(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError during passive reconnaissance: %s%s\n", colors.RED, err, colors.NC)
			if config.Mode == core.ModePassive {
				os.Exit(1)
			}
			// For auto mode, continue with active scan if IP ranges provided
		}

		if !config.Quiet {
			fmt.Printf("%s[+] Passive reconnaissance complete: %d IPs discovered%s\n", colors.GREEN, len(passiveIPs), colors.NC)
			fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n\n", colors.CYAN, colors.NC)
		}

		// If passive-only mode, we're done
		if config.Mode == core.ModePassive {
			// Output passive results and exit
			if len(passiveIPs) == 0 {
				fmt.Fprintf(os.Stderr, "%sNo IPs discovered from passive sources%s\n", colors.YELLOW, colors.NC)
				os.Exit(1)
			}

			// Save passive results if -o flag is used
			if outputFlagProvided {
				outputFile := config.OutputFile
				// If -o flag is used without value, auto-generate filename
				if outputFile == "" {
					outputFile = generatePassiveFilename(config.Domain)
				}
				if err := savePassiveResults(outputFile, passiveIPs, config.Domain); err != nil {
					fmt.Fprintf(os.Stderr, "%sError saving results: %s%s\n", colors.RED, err, colors.NC)
					os.Exit(1)
				}
				fmt.Printf("%s[+] Results saved to: %s%s\n", colors.GREEN, outputFile, colors.NC)
			}
			// Always show results on console too
			fmt.Printf("\n%sDiscovered IPs:%s\n", colors.CYAN, colors.NC)
			for _, ipAddr := range passiveIPs {
				fmt.Printf("  %s\n", ipAddr)
			}
			os.Exit(0)
		}

		// Auto mode: use discovered IPs for active scan
		if config.Mode == core.ModeAuto {
			if len(passiveIPs) > 0 {
				// Convert discovered IPs to IP ranges for scanning
				// If expand-netmask was provided (e.g., -n /24 or -n 24), expand each IP to that CIDR
				if config.ExpandNetmask != "" {
					// CIDR expansion mode: expand each discovered IP to its /X network
					// Normalize netmask (add / if missing)
					cidrBits := config.ExpandNetmask
					if cidrBits[0] != '/' {
						cidrBits = "/" + cidrBits
					}
					for _, ipAddr := range passiveIPs {
						expandedRange, err := expandIPToCIDR(ipAddr, cidrBits)
						if err == nil {
							config.IPRanges = append(config.IPRanges, expandedRange)
						}
					}
					if !config.Quiet {
						fmt.Printf("%s[*] Expanded %d IPs to %s networks for scanning%s\n\n", colors.CYAN, len(passiveIPs), config.ExpandNetmask, colors.NC)
					}
				} else {
					// Regular mode: scan discovered IPs only
					for _, ipAddr := range passiveIPs {
						ipInt, err := ip.ToUint32(net.ParseIP(ipAddr))
						if err == nil {
							config.IPRanges = append(config.IPRanges, [2]uint32{ipInt, ipInt})
						}
					}
					if !config.Quiet {
						fmt.Printf("\n%s[*] Proceeding with active scan on %d discovered IPs%s\n", colors.CYAN, len(passiveIPs), colors.NC)
					}
				}
				// Deduplicate after expansion
				config.IPRanges = deduplicateIPRanges(config.IPRanges)
			} else if len(config.IPRanges) == 0 {
				fmt.Fprintf(os.Stderr, "%sNo IPs discovered from passive scan and no IP ranges provided%s\n", colors.YELLOW, colors.NC)
				fmt.Fprintf(os.Stderr, "Try providing IP ranges manually: -n 192.168.1.0/24\n")
				os.Exit(1)
			}
		}
	}

	// Auto-generate WAF database if it doesn't exist
	wafPath := getWAFDatabasePath()
	if config.SkipWAF && !fileExists(wafPath) {
		// Try fallback to repo default
		if !fileExists("data/waf_ranges.json") {
			if !config.Quiet {
				fmt.Printf("%s[*] WAF database not found, generating from provider APIs...%s\n", colors.CYAN, colors.NC)
			}
			if err := updateWAFDatabase(); err != nil {
				fmt.Fprintf(os.Stderr, "%s[!] Warning: Failed to generate WAF database: %s%s\n", colors.YELLOW, err, colors.NC)
				fmt.Fprintf(os.Stderr, "%s[*] Continuing without WAF filtering%s\n", colors.YELLOW, colors.NC)
				config.SkipWAF = false
			} else if !config.Quiet {
				fmt.Printf("%s[+] WAF database generated successfully%s\n", colors.GREEN, colors.NC)
			}
		} else {
			// Copy repo default to user cache
			if data, err := os.ReadFile("data/waf_ranges.json"); err == nil {
				os.WriteFile(wafPath, data, 0644)
			}
		}
	}

	// Parse IP ranges (only for pure active mode, not auto/passive)
	if config.Mode == core.ModeActive || (config.Mode == "" && (config.StartIP != "" || config.CIDR != "" || config.InputFile != "" || config.ASN != "")) {
		if err := parseIPRanges(config); err != nil {
			fmt.Fprintf(os.Stderr, "%sError: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}

		// Deduplicate and merge overlapping IP ranges
		config.IPRanges = deduplicateIPRanges(config.IPRanges)
	}

	// Create scanner (only for active/auto modes)
	var s *scanner.Scanner
	if config.Mode != core.ModePassive {
		var err error
		s, err = scanner.New(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError creating scanner: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
	}

	// Print active scan header for auto mode
	if !config.Quiet && config.Mode == core.ModeAuto {
		fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n", colors.CYAN, colors.NC)
		fmt.Printf("%s  Starting Active Scan%s\n", colors.BOLD, colors.NC)
		fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n\n", colors.CYAN, colors.NC)
	}

	// Auto-generate filename if -o flag is used without value
	if outputFlagProvided && config.OutputFile == "" {
		if config.Mode == core.ModeAuto {
			config.OutputFile = generateAutoFilename(config.Domain)
		} else {
			config.OutputFile = generateActiveFilename(config.Domain)
		}
	}

	// Create output writer (empty string means console only)
	formatter := output.NewFormatter(config.Format, !config.NoColor, config.ShowAll)
	writer, err := output.NewWriter(config.OutputFile, formatter, config.Quiet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError creating output writer: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}
	defer writer.Close()

	// Write header
	// Calculate total IPs from ranges
	ranges := make([]ip.IPRange, len(config.IPRanges))
	for i, r := range config.IPRanges {
		ranges[i] = ip.IPRange{Start: r[0], End: r[1]}
	}
	iterator := ip.NewIterator(ranges)
	totalIPs := iterator.TotalIPs()
	writer.WriteHeader(config, totalIPs)

	// Create progress tracker
	var prog *output.Progress
	if !config.NoProgress && !config.Quiet {
		prog = output.NewProgress(totalIPs, true, !config.NoColor)
		go prog.Display()

		// Set progress callback
		s.SetProgressCallback(func(scanned, _ uint64) {
			prog.Update(scanned)
		})

		// Set progress stopper so scanner can stop it before validation
		s.SetProgressStopper(func() {
			prog.Stop()
		})
	}

	// Perform scan
	ctx := context.Background()
	result, err := s.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError during scan: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}

	// Stop progress display if not already stopped (validation stops it early)
	if prog != nil && prog.IsRunning() {
		prog.Stop()
		time.Sleep(150 * time.Millisecond) // Let display goroutine finish
		fmt.Println()                      // Blank line after progress bar
	}

	// Write results after scanning completes (descending order: errors → 200 OK near summary)
	if config.ShowAll {
		// Write errors first (least important, scroll past)
		for _, r := range result.Errors {
			writer.WriteResult(*r)
		}
		for _, r := range result.Timeouts {
			writer.WriteResult(*r)
		}
		for _, r := range result.Other {
			writer.WriteResult(*r)
		}
		for _, r := range result.Redirects {
			writer.WriteResult(*r)
		}
	}
	// Write 200 OK last (most important, near summary)
	for _, r := range result.Success {
		writer.WriteResult(*r)
	}

	// Show content hash analysis if --verify was used
	if config.VerifyContent && len(result.Success) > 0 {
		hashGroups := make(map[string][]*core.IPResult)
		for _, r := range result.Success {
			if r.BodyHash != "" {
				hashGroups[r.BodyHash] = append(hashGroups[r.BodyHash], r)
			}
		}

		// Show hash analysis if we have groups
		if len(hashGroups) > 0 && !config.Quiet {
			analysis := formatter.FormatDuplicateStats(hashGroups)
			fmt.Print(analysis)
		}

		// Filter results to show only unique hashes if --filter-unique flag used
		if config.FilterUnique {
			var uniqueResults []*core.IPResult
			for _, results := range hashGroups {
				if len(results) == 1 {
					uniqueResults = append(uniqueResults, results[0])
				}
			}

			// Replace success list with unique ones
			if len(uniqueResults) > 0 {
				result.Success = uniqueResults
				if !config.Quiet {
					fmt.Printf("\n%s[*] Filtered to %d unique response(s)%s\n", colors.GREEN, len(uniqueResults), colors.NC)
				}
			}
		}
	}

	// Write summary
	writer.WriteSummary(result.Summary)

	// Warn if many timeouts/errors and high worker count (possible rate limiting)
	totalFailed := uint64(len(result.Timeouts)) + uint64(len(result.Errors))
	if !config.Quiet && totalFailed > 0 && result.Summary.SuccessCount == 0 && config.Workers >= 10 {
		failureRate := float64(totalFailed) / float64(result.Summary.ScannedIPs) * 100
		if failureRate > 50 {
			fmt.Fprintf(os.Stderr, "\n%s[!] Warning: %.0f%% of requests failed%s\n", colors.YELLOW, failureRate, colors.NC)
			fmt.Fprintf(os.Stderr, "%s[!] The server may be rate-limiting connections%s\n", colors.YELLOW, colors.NC)
			fmt.Fprintf(os.Stderr, "%s[*] Try: Reduce workers (-j 5) and increase timeout (-t 10)%s\n", colors.CYAN, colors.NC)

			// Build example command without redundant flags
			exampleCmd := getRerunCommand(config)
			if !strings.Contains(exampleCmd, "-j") {
				exampleCmd += " -j 5"
			}
			if !strings.Contains(exampleCmd, "-t") {
				exampleCmd += " -t 10"
			}
			fmt.Fprintf(os.Stderr, "%s    Example: %s%s\n", colors.CYAN, exampleCmd, colors.NC)
		}
	}

	// Exit
	if len(result.Success) > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func parseFlags() (*core.Config, bool) {
	config := core.DefaultConfig()

	// Config file flag
	var configFile string
	pflag.StringVar(&configFile, "config", "", "Config file path (YAML)")

	// Global config flags
	initConfig := pflag.Bool("init-config", false, "Initialize global config file")
	showConfigPath := pflag.Bool("show-config", false, "Show global config file path")

	// Update flags
	doUpdate := pflag.Bool("update", false, "Check and install updates")
	updateWAF := pflag.Bool("update-waf", false, "Update WAF IP ranges database")

	// Basic flags
	pflag.StringVarP(&config.Domain, "domain", "d", "", "Target domain (required)")

	// IP range flags
	pflag.StringVarP(&config.StartIP, "start-ip", "s", "", "Start IP address")
	pflag.StringVarP(&config.EndIP, "end-ip", "e", "", "End IP address")
	pflag.StringVarP(&config.CIDR, "cidr", "c", "", "CIDR notation (e.g., 192.168.1.0/24)")
	pflag.StringVarP(&config.InputFile, "input", "i", "", "Input file with IPs/CIDRs")
	// Input scrape flag: generic scrape
	var inputScrape string
	pflag.StringVar(&inputScrape, "input-scrape", "", "Scrape IPs from file and use as input (writes <domain>-ips.txt and uses it)")
	pflag.StringVar(&config.ASN, "asn", "", "ASN lookup, comma-separated (e.g., AS4775,AS9299 or 4775,9299)")
	pflag.StringVarP(&config.ExpandNetmask, "expand-netmask", "n", "", "Expand IPs to subnet (e.g., /24 or 24) [works with passive mode and -i input file]")

	// Performance flags
	pflag.IntVarP(&config.Workers, "threads", "j", 10, "Number of parallel workers")

	// HTTP flags
	pflag.StringVarP(&config.HTTPMethod, "method", "m", "GET", "HTTP method")
	var timeout int
	var connectTimeout int
	pflag.IntVarP(&timeout, "timeout", "t", 5, "HTTP timeout in seconds")
	pflag.IntVar(&connectTimeout, "connect-timeout", 3, "TCP connect timeout in seconds")
	pflag.StringVarP(&config.CustomHeader, "header", "H", "", "Custom header")
	pflag.StringVarP(&config.UserAgent, "user-agent", "A", "", "User-Agent: random, chrome, firefox, safari, edge, opera, brave, mobile, or custom string")
	pflag.BoolVar(&config.NoUserAgent, "no-ua", false, "Disable User-Agent header")
	followRedirectFlag := pflag.IntP("follow-redirect", "", 0, "Follow HTTP redirects (use alone for unlimited, or --follow-redirect=3 for max hops)")
	pflag.Lookup("follow-redirect").NoOptDefVal = "10" // Default to 10 when flag used without value
	pflag.BoolVar(&config.VerifyContent, "verify", false, "Extract title and hash response body for verification")
	pflag.BoolVar(&config.FilterUnique, "filter-unique", false, "Show only IPs with unique content (requires --verify)")

	// Proxy flags
	pflag.StringVarP(&config.ProxyURL, "proxy", "P", "", "Proxy URL (http://IP:PORT or socks5://IP:PORT)")
	pflag.BoolVar(&config.ProxyAuto, "proxy-auto", false, "Auto-fetch proxies from public lists")
	pflag.BoolVar(&config.ProxyRotate, "proxy-rotate", false, "Rotate through proxy list")
	pflag.BoolVar(&config.ProxyTest, "proxy-test", true, "Test proxy before use")

	// WAF filtering flags
	pflag.BoolVar(&config.SkipWAF, "skip-waf", false, "Skip known WAF/CDN IP ranges")
	var skipProviders string
	pflag.StringVar(&skipProviders, "skip-providers", "", "Comma-separated list of providers to skip")
	pflag.StringVar(&config.CustomWAFFile, "custom-waf", "", "Custom WAF ranges file (JSON or text)")
	pflag.BoolVar(&config.ShowSkipped, "show-skipped", false, "Display skipped IPs")
	pflag.BoolVar(&config.NoWAFUpdate, "no-waf-update", false, "Disable WAF database auto-update")

	// Passive scan flags
	pflag.BoolVar(&config.PassiveOnly, "passive", false, "Passive reconnaissance only")
	pflag.BoolVar(&config.AutoScan, "auto-scan", false, "Auto-scan: passive then active")
	pflag.Float64Var(&config.MinConfidence, "min-confidence", 0.7, "Minimum confidence score (0.0-1.0)")
	var passiveSources string
	pflag.StringVar(&passiveSources, "passive-sources", "", "Comma-separated passive sources (ct,dns,shodan,censys)")

	// Output flags
	outputFlag := pflag.StringP("output", "o", "", "Output file path (use '-o' alone for auto-generated name, or '-o=file.txt' for custom)")
	pflag.Lookup("output").NoOptDefVal = "auto" // Allow -o without value (requires = when specifying filename)
	var format string
	pflag.StringVarP(&format, "format", "f", "text", "Output format (text|json|csv)")
	pflag.BoolVarP(&config.Quiet, "quiet", "q", false, "Quiet mode")
	pflag.BoolVarP(&config.ShowAll, "show-all", "a", false, "Show all responses")
	pflag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")
	pflag.BoolVar(&config.NoProgress, "no-progress", false, "Disable progress bar")
	pflag.BoolVar(&config.SilentErrors, "silent-errors", false, "Suppress passive source API error warnings")

	// Version flag
	showVersion := pflag.BoolP("version", "V", false, "Show version")

	pflag.Parse()

	// Handle --follow-redirect flag
	config.MaxRedirects = *followRedirectFlag

	// Check if -o flag was provided
	outputFlagProvided := pflag.Lookup("output").Changed
	config.OutputFile = *outputFlag

	// Auto-generate filename if -o was used without value
	if outputFlagProvided && config.OutputFile == "auto" {
		// Will be set later based on mode
		config.OutputFile = "" // Mark for later generation
	}

	// Handle --show-config
	if *showConfigPath {
		configPath, err := core.GetGlobalConfigPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		fmt.Printf("Global config path: %s\n", configPath)
		os.Exit(0)
	}

	// Handle --init-config
	if *initConfig {
		if err := initializeGlobalConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "%sError: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle --update-waf
	if *updateWAF {
		fmt.Printf("%s[*] Updating WAF IP ranges database...%s\n", colors.CYAN, colors.NC)
		if err := updateWAFDatabase(); err != nil {
			fmt.Fprintf(os.Stderr, "%sWAF update failed: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		fmt.Printf("%s[+] WAF database updated successfully%s\n", colors.GREEN, colors.NC)
		os.Exit(0)
	}

	// Handle update
	if *doUpdate {
		if err := update.Update(); err != nil {
			fmt.Fprintf(os.Stderr, "%sUpdate failed: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle version
	if *showVersion {
		fmt.Printf("origindive v%s\n", version.Version)
		fmt.Printf("Go version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Load global config first (lowest priority)
	globalConfig, err := core.LoadGlobalConfig()
	if err != nil {
		// Non-fatal: just use defaults if global config doesn't exist
		globalConfig = core.DefaultGlobalConfig()
	}

	// Load scan-specific config file if specified (medium priority)
	if configFile != "" {
		fileConfig, err := core.LoadFromFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError loading config file: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		// Merge with CLI flags (CLI takes precedence)
		cliConfig := config
		config = fileConfig
		config.MergeWithCLI(cliConfig)
	}

	// Merge global config (CLI and scan config take precedence)
	globalConfig.MergeIntoConfig(config)

	// Parse durations
	config.Timeout = time.Duration(timeout) * time.Second
	config.ConnectTimeout = time.Duration(connectTimeout) * time.Second

	// Parse format
	switch strings.ToLower(format) {
	case "text":
		config.Format = core.FormatText
	case "json":
		config.Format = core.FormatJSON
	case "csv":
		config.Format = core.FormatCSV
	default:
		fmt.Fprintf(os.Stderr, "Invalid format: %s\n", format)
		os.Exit(1)
	}

	// Parse skip providers
	if skipProviders != "" {
		config.SkipProviders = strings.Split(skipProviders, ",")
	}

	// Parse passive sources
	if passiveSources != "" {
		config.PassiveSources = strings.Split(passiveSources, ",")
	}

	// Handle input scrape flag (--input-scrape)
	if inputScrape != "" {
		if config.Domain == "" {
			fmt.Fprintf(os.Stderr, "%sError: domain required when using --input-scrape%s\n", colors.RED, colors.NC)
			os.Exit(1)
		}

		outFile, err := scrapeIPsFromFile(inputScrape, config.Domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError processing input file: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		config.InputFile = outFile
	}

	// Validate -n flag: should be just a mask, not a full CIDR
	// Warn users to use -c for CIDR notation
	if config.ExpandNetmask != "" {
		// Check if it looks like a full CIDR (contains IP address)
		if strings.Contains(config.ExpandNetmask, ".") || strings.Contains(config.ExpandNetmask, ":") {
			fmt.Fprintf(os.Stderr, "%s[!] Error: -n flag is for netmask expansion in passive mode (e.g., -n /24)%s\n", colors.RED, colors.NC)
			fmt.Fprintf(os.Stderr, "%s[!] For CIDR notation, use -c flag instead:%s\n", colors.RED, colors.NC)
			fmt.Fprintf(os.Stderr, "%s    Example: -c %s%s\n", colors.CYAN, config.ExpandNetmask, colors.NC)
			os.Exit(1)
		}
	}

	// Set scan mode based on flags
	if config.PassiveOnly {
		config.Mode = core.ModePassive
	} else if config.AutoScan {
		config.Mode = core.ModeAuto
	} else {
		// Default: If only domain provided, do auto-scan (passive + active)
		// If IP ranges provided (IP range, CIDR, input file, or ASN), do active scan
		if config.StartIP == "" && config.CIDR == "" && config.InputFile == "" && config.ASN == "" {
			config.Mode = core.ModeAuto // Auto-scan when only domain provided
			config.AutoScan = true      // Enable auto-scan flag
		} else {
			config.Mode = core.ModeActive // Active scan when IP ranges provided
		}
	}

	return config, outputFlagProvided
}

// initializeGlobalConfig creates and saves a global config file with prompts
func initializeGlobalConfig() error {
	colors.Init(true)

	configPath, err := core.GetGlobalConfigPath()
	if err != nil {
		return err
	}

	fmt.Printf("%s╔═══════════════════════════════════════════════════════════════╗%s\n", colors.CYAN, colors.NC)
	fmt.Printf("%s║           origindive - Global Config Setup                    ║%s\n", colors.CYAN, colors.NC)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", colors.CYAN, colors.NC)

	fmt.Printf("This will create a global configuration file at:\n")
	fmt.Printf("%s%s%s\n\n", colors.YELLOW, configPath, colors.NC)

	// Create scanner for input
	scanner := bufio.NewScanner(os.Stdin)

	// Check if file already exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("%sWarning: Config file already exists!%s\n", colors.YELLOW, colors.NC)
		fmt.Print("Overwrite? (y/N): ")
		if scanner.Scan() {
			response := strings.TrimSpace(scanner.Text())
			if strings.ToLower(response) != "y" {
				fmt.Println("Cancelled.")
				return nil
			}
		}
		fmt.Println()
	}

	config := core.DefaultGlobalConfig()

	fmt.Printf("%sAPI Keys Setup (optional - press Enter to skip)%s\n", colors.GREEN, colors.NC)
	fmt.Println(strings.Repeat("─", 63))

	// Shodan keys
	fmt.Printf("\n%sShodan API Keys%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API key: https://account.shodan.io/ | Docs: https://developer.shodan.io/api\n")
	fmt.Println("Enter keys one at a time (empty line to finish):")
	var shodanKeys []string
	for i := 1; ; i++ {
		fmt.Printf("  Key #%d: ", i)
		if !scanner.Scan() {
			break
		}
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}
		shodanKeys = append(shodanKeys, key)
	}
	if len(shodanKeys) > 0 {
		config.ShodanKeys = shodanKeys
		fmt.Printf("%s✓ Added %d Shodan key(s)%s\n", colors.GREEN, len(shodanKeys), colors.NC)
	}

	// Censys API tokens
	fmt.Printf("\n%sCensys API Tokens%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API token: https://accounts.censys.io/settings/personal-access-tokens | Docs: https://docs.censys.com/reference/get-started\n")
	fmt.Println("Enter API tokens one at a time (empty line to finish):")
	var censysTokens []string
	for i := 1; ; i++ {
		fmt.Printf("  Token #%d: ", i)
		if !scanner.Scan() {
			break
		}
		token := strings.TrimSpace(scanner.Text())
		if token == "" {
			break
		}
		censysTokens = append(censysTokens, token)
	}
	if len(censysTokens) > 0 {
		config.CensysTokens = censysTokens
		fmt.Printf("%s✓ Added %d Censys token(s)%s\n", colors.GREEN, len(censysTokens), colors.NC)

		// Prompt for Organization ID (required for API)
		fmt.Printf("\n%sCensys Organization ID%s (required for API access)\n", colors.CYAN, colors.NC)
		fmt.Printf("  Org ID: ")
		if scanner.Scan() {
			orgID := strings.TrimSpace(scanner.Text())
			if orgID != "" {
				config.CensysOrgID = orgID
				fmt.Printf("%s✓ Added Censys Org ID%s\n", colors.GREEN, colors.NC)
			}
		}
	}

	// SecurityTrails keys
	fmt.Printf("\n%sSecurityTrails API Keys%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API key: https://securitytrails.com/app/account/credentials | Docs: https://securitytrails.com/app/account/docs-and-examples\n")
	fmt.Println("Enter keys one at a time (empty line to finish):")
	var securitytrailsKeys []string
	for i := 1; ; i++ {
		fmt.Printf("  Key #%d: ", i)
		if !scanner.Scan() {
			break
		}
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}
		securitytrailsKeys = append(securitytrailsKeys, key)
	}
	if len(securitytrailsKeys) > 0 {
		config.SecurityTrailsKeys = securitytrailsKeys
		fmt.Printf("%s✓ Added %d SecurityTrails key(s)%s\n", colors.GREEN, len(securitytrailsKeys), colors.NC)
	}

	// VirusTotal keys
	fmt.Printf("\n%sVirusTotal API Keys%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API key: https://www.virustotal.com/gui/user/[USERNAME]/apikey | Docs: https://docs.virustotal.com/reference/overview\n")
	fmt.Println("Enter keys one at a time (empty line to finish):")
	var virustotalKeys []string
	for i := 1; ; i++ {
		fmt.Printf("  Key #%d: ", i)
		if !scanner.Scan() {
			break
		}
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}
		virustotalKeys = append(virustotalKeys, key)
	}
	if len(virustotalKeys) > 0 {
		config.VirusTotalKeys = virustotalKeys
		fmt.Printf("%s✓ Added %d VirusTotal key(s)%s\n", colors.GREEN, len(virustotalKeys), colors.NC)
	}

	// ZoomEye keys
	fmt.Printf("\n%sZoomEye API Keys%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API key: https://www.zoomeye.ai/profile | Docs: https://www.zoomeye.ai/doc\n")
	fmt.Println("Enter keys one at a time (empty line to finish):")
	var zoomeyeKeys []string
	for i := 1; ; i++ {
		fmt.Printf("  Key #%d: ", i)
		if !scanner.Scan() {
			break
		}
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}
		zoomeyeKeys = append(zoomeyeKeys, key)
	}
	if len(zoomeyeKeys) > 0 {
		config.ZoomEyeKeys = zoomeyeKeys
		fmt.Printf("%s✓ Added %d ZoomEye key(s)%s\n", colors.GREEN, len(zoomeyeKeys), colors.NC)
	}

	// ViewDNS keys
	fmt.Printf("\n%sViewDNS API Keys%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API key: https://viewdns.info/dashboard/api/account-details/ | Docs: https://viewdns.info/api/\n")
	fmt.Println("Enter keys one at a time (empty line to finish):")
	var viewdnsKeys []string
	for i := 1; ; i++ {
		fmt.Printf("  Key #%d: ", i)
		if !scanner.Scan() {
			break
		}
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}
		viewdnsKeys = append(viewdnsKeys, key)
	}
	if len(viewdnsKeys) > 0 {
		config.ViewDNSKeys = viewdnsKeys
		fmt.Printf("%s✓ Added %d ViewDNS key(s)%s\n", colors.GREEN, len(viewdnsKeys), colors.NC)
	}

	// DNSDumpster keys
	fmt.Printf("\n%sDNSDumpster API Keys%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API key: https://dnsdumpster.com/my-account/ | Docs: https://dnsdumpster.com/developer/\n")
	fmt.Println("Enter keys one at a time (empty line to finish):")
	var dnsdumpsterKeys []string
	for i := 1; ; i++ {
		fmt.Printf("  Key #%d: ", i)
		if !scanner.Scan() {
			break
		}
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}
		dnsdumpsterKeys = append(dnsdumpsterKeys, key)
	}
	if len(dnsdumpsterKeys) > 0 {
		config.DNSDumpsterKeys = dnsdumpsterKeys
		fmt.Printf("%s✓ Added %d DNSDumpster key(s)%s\n", colors.GREEN, len(dnsdumpsterKeys), colors.NC)
	}

	// Webshare proxy keys
	fmt.Printf("\n%sWebshare Proxy API Keys%s\n", colors.CYAN, colors.NC)
	fmt.Printf("Get API key: https://dashboard.webshare.io/userapi/keys | Docs: https://apidocs.webshare.io/\n")
	fmt.Println("Enter keys one at a time (empty line to finish):")
	var webshareKeys []string
	for i := 1; ; i++ {
		fmt.Printf("  Key #%d: ", i)
		if !scanner.Scan() {
			break
		}
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}
		webshareKeys = append(webshareKeys, key)
	}
	if len(webshareKeys) > 0 {
		config.WebshareKeys = webshareKeys
		fmt.Printf("%s✓ Added %d Webshare key(s)%s\n", colors.GREEN, len(webshareKeys), colors.NC)

		// Optional: Webshare Plan IDs
		fmt.Printf("\n%sWebshare Plan IDs (optional - press Enter to skip)%s\n", colors.CYAN, colors.NC)
		fmt.Println("Enter plan IDs one at a time (maps 1:1 with keys, empty line to finish):")
		var websharePlanIDs []string
		for i := 1; i <= len(webshareKeys); i++ {
			fmt.Printf("  Plan ID for Key #%d: ", i)
			if !scanner.Scan() {
				break
			}
			planID := strings.TrimSpace(scanner.Text())
			if planID == "" {
				break
			}
			websharePlanIDs = append(websharePlanIDs, planID)
		}
		if len(websharePlanIDs) > 0 {
			config.WebsharePlanIDs = websharePlanIDs
			fmt.Printf("%s✓ Added %d Plan ID(s)%s\n", colors.GREEN, len(websharePlanIDs), colors.NC)
		}
	}

	fmt.Printf("\n%sDefault Settings (press Enter to use defaults shown)%s\n", colors.GREEN, colors.NC)
	fmt.Println(strings.Repeat("─", 63))

	// Workers
	fmt.Printf("\nWorkers [%d]: ", config.Workers)
	if scanner.Scan() {
		workersStr := strings.TrimSpace(scanner.Text())
		if workersStr != "" {
			var workers int
			if _, err := fmt.Sscanf(workersStr, "%d", &workers); err == nil && workers > 0 {
				config.Workers = workers
			}
		}
	}

	// Timeout
	fmt.Printf("Timeout [%s]: ", config.Timeout)
	if scanner.Scan() {
		timeoutStr := strings.TrimSpace(scanner.Text())
		if timeoutStr != "" {
			config.Timeout = timeoutStr
		}
	}

	// Format
	fmt.Printf("Default format (text/json/csv) [%s]: ", config.Format)
	if scanner.Scan() {
		formatStr := strings.TrimSpace(scanner.Text())
		if formatStr != "" {
			config.Format = formatStr
		}
	}

	// Skip WAF
	fmt.Printf("Skip WAF/CDN ranges by default? (y/N) [%v]: ", config.SkipWAF)
	if scanner.Scan() {
		skipStr := strings.TrimSpace(scanner.Text())
		if skipStr != "" {
			config.SkipWAF = strings.ToLower(skipStr) == "y"
		}
	}

	// Save config
	if err := core.SaveGlobalConfig(config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("\n%s✓ Global config saved successfully!%s\n", colors.GREEN, colors.NC)
	fmt.Printf("\nYou can now run scans without specifying these settings:\n")
	fmt.Printf("  %sorigindive -d example.com -n 192.168.1.0/24%s\n\n", colors.CYAN, colors.NC)
	fmt.Printf("Edit config anytime at: %s%s%s\n", colors.YELLOW, configPath, colors.NC)

	return nil
}

func validateConfig(config *core.Config) error {
	if config.Domain == "" {
		return fmt.Errorf("domain is required (-d or --domain)")
	}

	// Validate --filter-unique requires --verify
	if config.FilterUnique && !config.VerifyContent {
		return fmt.Errorf("--filter-unique requires --verify flag")
	}

	// For passive-only mode, IP ranges are not needed
	// For auto mode, IP ranges are optional (will be discovered from passive scan)
	// For active mode, IP ranges are required
	if config.Mode == core.ModeActive || config.Mode == "" {
		if config.StartIP == "" && config.CIDR == "" && config.InputFile == "" && config.ASN == "" {
			return fmt.Errorf("must specify IP range for active scan: -s/-e, -n, -i, or --asn (or use --passive/--auto-scan)")
		}
	}

	// If start IP specified, end IP must also be specified
	if config.StartIP != "" && config.EndIP == "" {
		return fmt.Errorf("both start IP (-s) and end IP (-e) required for range mode")
	}

	return nil
}

func parseIPRanges(config *core.Config) error {
	var ranges [][2]uint32

	// Handle ASN lookup first (supports comma-separated ASNs)
	if config.ASN != "" {
		asnList := strings.Split(config.ASN, ",")
		asnClient := asn.NewClient("")
		totalASNRanges := 0

		for _, asnInput := range asnList {
			asnInput = strings.TrimSpace(asnInput)
			if asnInput == "" {
				continue
			}

			if !config.Quiet {
				fmt.Printf("%s[*] Looking up ASN %s...%s\n", colors.CYAN, asnInput, colors.NC)
			}

			asnResp, err := asnClient.LookupASN(asnInput)
			if err != nil {
				return fmt.Errorf("ASN lookup failed for %s: %w", asnInput, err)
			}

			if !config.Quiet {
				fmt.Printf("%s[+] Found %d CIDR ranges for AS%d (%s)%s\n",
					colors.GREEN, len(asnResp.ASNRanges), asnResp.ASN, asnResp.ASNName, colors.NC)
			}

			// Parse each CIDR from ASN response
			for _, cidr := range asnResp.ASNRanges {
				r, err := ip.ParseCIDRRange(cidr)
				if err != nil {
					if !config.Quiet {
						fmt.Fprintf(os.Stderr, "%s[!] Warning: Invalid CIDR %s: %s%s\n",
							colors.YELLOW, cidr, err, colors.NC)
					}
					continue
				}
				ranges = append(ranges, [2]uint32{r.Start, r.End})
				totalASNRanges++
			}
		}

		if len(ranges) == 0 {
			return fmt.Errorf("no valid IP ranges found in ASN(s): %s", config.ASN)
		}

		if !config.Quiet && len(asnList) > 1 {
			fmt.Printf("%s[+] Total: %d CIDR ranges from %d ASN(s)%s\n",
				colors.GREEN, totalASNRanges, len(asnList), colors.NC)
		}
	}

	// Parse IP range
	if config.StartIP != "" && config.EndIP != "" {
		r, err := ip.ParseIPRange(config.StartIP, config.EndIP)
		if err != nil {
			return fmt.Errorf("invalid IP range: %w", err)
		}
		ranges = append(ranges, [2]uint32{r.Start, r.End})
	}

	// Parse CIDR
	if config.CIDR != "" {
		r, err := ip.ParseCIDRRange(config.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %w", err)
		}
		ranges = append(ranges, [2]uint32{r.Start, r.End})
	}

	// Parse input file
	if config.InputFile != "" {
		fileRanges, err := ip.ParseInputFile(config.InputFile)
		if err != nil {
			return fmt.Errorf("failed to parse input file: %w", err)
		}

		// If expand-netmask is provided, expand each IP to its subnet
		if config.ExpandNetmask != "" {
			// Normalize netmask (add / if missing)
			cidrBits := config.ExpandNetmask
			if cidrBits[0] != '/' {
				cidrBits = "/" + cidrBits
			}

			expandedCount := 0
			for _, r := range fileRanges {
				// For each IP in the range, expand to subnet
				// If it's a single IP (Start == End), expand it
				if r.Start == r.End {
					ipAddr := ip.FromUint32(r.Start)
					expandedRange, err := expandIPToCIDR(ipAddr.String(), cidrBits)
					if err == nil {
						ranges = append(ranges, expandedRange)
						expandedCount++
					}
				} else {
					// If it's already a range, keep it as-is
					ranges = append(ranges, [2]uint32{r.Start, r.End})
				}
			}

			if !config.Quiet && expandedCount > 0 {
				fmt.Printf("%s[*] Expanded %d IPs from input file to %s networks%s\n\n",
					colors.CYAN, expandedCount, config.ExpandNetmask, colors.NC)
			}
		} else {
			// No expansion, use as-is
			for _, r := range fileRanges {
				ranges = append(ranges, [2]uint32{r.Start, r.End})
			}
		}
	}

	config.IPRanges = ranges
	return nil
}

// scrapeIPsFromFile reads any file, extracts IPv4 addresses using a regex,
// writes them to '<domain>-ips.txt' (one per line) and returns the filename.
func scrapeIPsFromFile(path, domain string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}

	re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	matches := re.FindAllString(string(data), -1)

	seen := make(map[string]bool)
	var ips []string
	for _, m := range matches {
		ipObj := net.ParseIP(m)
		if ipObj == nil || ipObj.To4() == nil {
			continue
		}
		if seen[m] {
			continue
		}
		seen[m] = true
		ips = append(ips, m)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found in %s", path)
	}

	sort.Strings(ips)
	outName := fmt.Sprintf("%s-ips.txt", domain)
	if err := os.WriteFile(outName, []byte(strings.Join(ips, "\n")), 0644); err != nil {
		return "", fmt.Errorf("failed to write output file: %w", err)
	}

	return outName, nil
}

// (Previously had a Censys-specific parser; removed in favor of generic scrape.)

// runPassiveRecon performs passive reconnaissance to discover IPs related to the domain
func runPassiveRecon(config *core.Config) ([]string, error) {
	var discoveredIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Channel for collecting IPs from different sources
	ipChan := make(chan string, 100)

	// Start goroutines for each passive source (if enabled)
	sources := getEnabledPassiveSources(config)
	wg.Add(len(sources))

	for _, source := range sources {
		go func(src string) {
			defer wg.Done()
			ips, err := queryPassiveSource(src, config)
			if err != nil {
				if !config.Quiet && !config.SilentErrors {
					fmt.Fprintf(os.Stderr, "%s[!] %s: %s%s\n", colors.YELLOW, src, err, colors.NC)
				}
				return
			}
			for _, ipAddr := range ips {
				ipChan <- ipAddr
			}
		}(source)
	}

	// Wait for all sources to complete
	go func() {
		wg.Wait()
		close(ipChan)
	}()

	// Collect unique IPs
	seen := make(map[string]bool)
	for ipAddr := range ipChan {
		mu.Lock()
		if !seen[ipAddr] {
			seen[ipAddr] = true
			discoveredIPs = append(discoveredIPs, ipAddr)
		}
		mu.Unlock()
	}

	return discoveredIPs, nil
}

// getEnabledPassiveSources returns list of passive sources to query
func getEnabledPassiveSources(config *core.Config) []string {
	// Parse passive sources from config
	if len(config.PassiveSources) == 0 {
		return []string{"ct", "dns"} // Default: free sources only
	}

	// PassiveSources is already a slice of strings
	return config.PassiveSources
}

// queryPassiveSource queries a specific passive intelligence source
func queryPassiveSource(source string, config *core.Config) ([]string, error) {
	if !config.Quiet {
		fmt.Printf("%s[*] Querying %s...%s\n", colors.CYAN, source, colors.NC)
	}

	switch strings.ToLower(source) {
	case "ct":
		// Certificate Transparency logs (free)
		return queryCertificateTransparency(config.Domain, config)
	case "dns":
		// DNS history (free via public resolvers)
		return queryDNSHistory(config.Domain, config)
	case "shodan":
		// Shodan API (requires key)
		return queryShodan(config.Domain, config)
	case "censys":
		// Censys API (requires key)
		return queryCensys(config.Domain, config)
	case "securitytrails":
		// SecurityTrails API (requires key)
		return querySecurityTrails(config.Domain, config)
	case "zoomeye":
		// ZoomEye API (requires key)
		return queryZoomEye(config.Domain, config)
	case "wayback":
		// Wayback Machine (free)
		return queryWayback(config.Domain, config)
	case "virustotal":
		// VirusTotal API (free tier with rate limits)
		return queryVirusTotal(config.Domain, config)
	case "viewdns":
		// ViewDNS API (requires key)
		return queryViewDNS(config.Domain, config)
	case "dnsdumpster":
		// DNSDumpster (free web scraping)
		return queryDNSDumpster(config.Domain, config)
	default:
		return nil, fmt.Errorf("unknown passive source: %s", source)
	}
}

// passiveTimeout returns the timeout to use for passive intelligence sources.
// It is at least 30s, but follows the CLI `-t` value if greater.
func passiveTimeout(config *core.Config) time.Duration {
	if config.Timeout > 30*time.Second {
		return config.Timeout
	}
	return 30 * time.Second
}

// queryCertificateTransparency searches CT logs for domain certificates
func queryCertificateTransparency(domain string, config *core.Config) ([]string, error) {
	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := ct.SearchCrtSh(ctx, domain, t)
	if err != nil {
		return []string{}, fmt.Errorf("CT search failed: %w", err)
	}

	return ips, nil
}

// queryDNSHistory queries DNS history and MX records for the domain
func queryDNSHistory(domain string, config *core.Config) ([]string, error) {
	var allIPs []string

	// Phase 1: Subdomain enumeration
	fmt.Printf("  → Enumerating subdomains...\n")
	t := passiveTimeout(config)
	subScanner := subdomain.NewScanner(domain, 20, t)
	ctx, cancel := context.WithTimeout(context.Background(), t*4)
	defer cancel()

	subResults, err := subScanner.Scan(ctx, subdomain.CommonSubdomains)
	if err == nil && len(subResults) > 0 {
		subIPs := subScanner.GetAllIPs()
		fmt.Printf("  → Found %d IPs from %d subdomains\n", len(subIPs), len(subResults))
		allIPs = append(allIPs, subIPs...)
	}

	// Phase 2: MX record analysis
	fmt.Printf("  → Analyzing MX records...\n")
	mxRecords, err := passivedns.LookupMX(ctx, domain, t)
	if err == nil && len(mxRecords) > 0 {
		mxIPs := passivedns.GetAllMXIPs(mxRecords)
		fmt.Printf("  → Found %d IPs from %d MX records\n", len(mxIPs), len(mxRecords))
		allIPs = append(allIPs, mxIPs...)
	}

	if len(allIPs) == 0 {
		return []string{}, fmt.Errorf("no IPs discovered from DNS enumeration")
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, ip := range allIPs {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}

	return unique, nil
}

// queryShodan searches Shodan for IPs hosting the domain
func queryShodan(domain string, config *core.Config) ([]string, error) {
	if len(config.ShodanKeys) == 0 {
		return []string{}, fmt.Errorf("no Shodan API keys configured")
	}

	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := shodan.SearchHostname(ctx, domain, config.ShodanKeys, t)
	if err != nil {
		return []string{}, fmt.Errorf("Shodan search failed: %w", err)
	}

	return ips, nil
}

// queryCensys searches Censys for IPs hosting the domain
func queryCensys(domain string, config *core.Config) ([]string, error) {
	if len(config.CensysTokens) == 0 {
		return []string{}, fmt.Errorf("no Censys PAT tokens configured")
	}

	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := censys.SearchHosts(ctx, domain, config.CensysTokens, config.CensysOrgID, t)
	if err != nil {
		return []string{}, fmt.Errorf("Censys search failed: %w", err)
	}

	return ips, nil
}

// querySecurityTrails searches SecurityTrails for subdomains and historical IPs
func querySecurityTrails(domain string, config *core.Config) ([]string, error) {
	if len(config.SecurityTrailsKeys) == 0 {
		return []string{}, fmt.Errorf("no SecurityTrails API keys configured")
	}

	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := securitytrails.SearchSubdomainsAndHistory(ctx, domain, config.SecurityTrailsKeys, t)
	if err != nil {
		return []string{}, fmt.Errorf("SecurityTrails search failed: %w", err)
	}

	return ips, nil
}

// queryZoomEye searches ZoomEye for hosts matching the domain
func queryZoomEye(domain string, config *core.Config) ([]string, error) {
	if len(config.ZoomEyeKeys) == 0 {
		return []string{}, fmt.Errorf("no ZoomEye API keys configured")
	}

	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := zoomeye.SearchHost(ctx, domain, config.ZoomEyeKeys, t)
	if err != nil {
		return []string{}, fmt.Errorf("ZoomEye search failed: %w", err)
	}

	return ips, nil
}

// queryWayback searches the Wayback Machine CDX API for historical subdomains
func queryWayback(domain string, config *core.Config) ([]string, error) {
	// Wayback Machine is free - no API key needed
	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := wayback.SearchSubdomains(ctx, domain, t)
	if err != nil {
		return []string{}, fmt.Errorf("Wayback Machine search failed: %w", err)
	}

	return ips, nil
}

// queryVirusTotal searches VirusTotal for subdomains and DNS records
func queryVirusTotal(domain string, config *core.Config) ([]string, error) {
	if len(config.VirusTotalKeys) == 0 {
		return []string{}, fmt.Errorf("no VirusTotal API keys configured")
	}

	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := virustotal.SearchSubdomains(ctx, domain, config.VirusTotalKeys, t)
	if err != nil {
		return []string{}, fmt.Errorf("VirusTotal search failed: %w", err)
	}

	return ips, nil
}

// queryViewDNS searches ViewDNS reverse IP for related domains
func queryViewDNS(domain string, config *core.Config) ([]string, error) {
	if len(config.ViewDNSKeys) == 0 {
		return []string{}, fmt.Errorf("no ViewDNS API keys configured")
	}

	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := viewdns.SearchReverseIP(ctx, domain, config.ViewDNSKeys, t)
	if err != nil {
		return []string{}, fmt.Errorf("ViewDNS search failed: %w", err)
	}

	return ips, nil
}

// queryDNSDumpster scrapes DNSDumpster for subdomains and IPs
func queryDNSDumpster(domain string, config *core.Config) ([]string, error) {
	if len(config.DNSDumpsterKeys) == 0 {
		return []string{}, fmt.Errorf("no DNSDumpster API keys configured")
	}

	t := passiveTimeout(config)
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	ips, err := dnsdumpster.SearchDomain(ctx, domain, config.DNSDumpsterKeys, t)
	if err != nil {
		return []string{}, fmt.Errorf("DNSDumpster search failed: %w", err)
	}

	return ips, nil
}

// savePassiveResults saves discovered IPs to output file
func savePassiveResults(outputPath string, ips []string, domain string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# Passive reconnaissance results for: %s\n", domain)
	fmt.Fprintf(file, "# Discovered at: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(file, "# Total IPs: %d\n\n", len(ips))

	// Write IPs
	for _, ipAddr := range ips {
		fmt.Fprintf(file, "%s\n", ipAddr)
	}

	return nil
}

// checkForUpdatesAsync checks for updates in the background without blocking
func checkForUpdatesAsync() {
	// Only check if not in quiet mode and not running special flags
	release, err := update.CheckForUpdate()
	if err != nil {
		// Silently fail - don't interrupt the user
		return
	}

	if release != nil {
		fmt.Printf("%s\n╔═══════════════════════════════════════════════════════════╗%s\n", colors.YELLOW, colors.NC)
		fmt.Printf("%s║  🎉 New version available: v%s (current: v%s)       ║%s\n", colors.YELLOW, release.LatestVersion, version.Version, colors.NC)
		fmt.Printf("%s║  Run: origindive --update                                 ║%s\n", colors.YELLOW, colors.NC)
		fmt.Printf("%s╚═══════════════════════════════════════════════════════════╝%s\n\n", colors.YELLOW, colors.NC)
		time.Sleep(2 * time.Second) // Let user see the notification
	}
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// autoInitializeGlobalConfig silently creates the global config on first run
func autoInitializeGlobalConfig() {
	configPath := getGlobalConfigPath()
	if fileExists(configPath) {
		return // Config already exists
	}

	// Create config directory
	configDir := getConfigDir()
	if err := os.MkdirAll(configDir, 0755); err != nil {
		// Silently continue if directory creation fails (user can create manually)
		return
	}

	// Copy example config to global location
	examplePath := "configs/global.example.yaml"
	if !fileExists(examplePath) {
		// If example doesn't exist, create minimal config
		minimalConfig := createMinimalGlobalConfig()
		if err := os.WriteFile(configPath, []byte(minimalConfig), 0600); err == nil {
			fmt.Printf("%s[+] Created global config: %s%s\n", colors.GREEN, configPath, colors.NC)
			fmt.Printf("%s[*] Edit this file to add API keys for passive reconnaissance%s\n\n", colors.CYAN, colors.NC)
		}
		return
	}

	// Copy example config
	exampleData, err := os.ReadFile(examplePath)
	if err != nil {
		return
	}

	if err := os.WriteFile(configPath, exampleData, 0600); err == nil {
		fmt.Printf("%s[+] Created global config: %s%s\n", colors.GREEN, configPath, colors.NC)
		fmt.Printf("%s[*] Edit this file to add API keys for passive reconnaissance%s\n\n", colors.CYAN, colors.NC)
	}
}

// getConfigDir returns the platform-specific config directory
func getConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	if runtime.GOOS == "windows" {
		// Windows: %USERPROFILE%\.config\origindive (consistent with Unix)
		return fmt.Sprintf("%s\\.config\\origindive", homeDir)
	}
	// Linux/macOS: ~/.config/origindive (XDG compliant)
	return fmt.Sprintf("%s/.config/origindive", homeDir)
}

// getGlobalConfigPath returns the full path to global config file
func getGlobalConfigPath() string {
	configDir := getConfigDir()
	if configDir == "" {
		return ""
	}
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("%s\\config.yaml", configDir)
	}
	return fmt.Sprintf("%s/config.yaml", configDir)
}

// getWAFDatabasePath returns the path to user's WAF database cache
// Returns user cache path (preferred) or repo default (fallback)
func getWAFDatabasePath() string {
	configDir := getConfigDir()
	if configDir == "" {
		return "data/waf_ranges.json" // Fallback to repo default
	}

	var userPath string
	if runtime.GOOS == "windows" {
		userPath = fmt.Sprintf("%s\\waf_ranges.json", configDir)
	} else {
		userPath = fmt.Sprintf("%s/waf_ranges.json", configDir)
	}

	// Check if user cache exists
	if fileExists(userPath) {
		return userPath
	}

	// User cache doesn't exist - copy repo default to user cache if available
	if fileExists("data/waf_ranges.json") {
		if data, err := os.ReadFile("data/waf_ranges.json"); err == nil {
			if err := os.WriteFile(userPath, data, 0644); err == nil {
				return userPath // Successfully copied to user cache
			}
		}
		// If copy failed, use repo default
		return "data/waf_ranges.json"
	}

	// Neither exists, return user path (will be created on update)
	return userPath
}

// createMinimalGlobalConfig creates a minimal config template
func createMinimalGlobalConfig() string {
	return `# origindive Global Configuration
# Auto-generated on first run
#
# Location:
#   Linux/macOS: ~/.config/origindive/config.yaml
#   Windows: %USERPROFILE%\.config\origindive\config.yaml

# ============================================================
# API Keys (Add your keys here)
# ============================================================

# Shodan API keys (https://account.shodan.io/)
shodan_keys:
  # - "YOUR_SHODAN_KEY_HERE"

# Censys API tokens (https://search.censys.io/account/api)
censys_tokens:
  # - "YOUR_CENSYS_API_TOKEN_HERE"

# SecurityTrails API keys (https://securitytrails.com/app/account/credentials)
securitytrails_keys:
  # - "YOUR_SECURITYTRAILS_KEY_HERE"

# VirusTotal API keys (https://www.virustotal.com/gui/user/[username]/apikey)
virustotal_keys:
  # - "YOUR_VIRUSTOTAL_KEY_HERE"

# ZoomEye API keys (https://www.zoomeye.org/profile)
zoomeye_keys:
  # - "YOUR_ZOOMEYE_KEY_HERE"

# ViewDNS API keys (https://viewdns.info/api/)
viewdns_keys:
  # - "YOUR_VIEWDNS_KEY_HERE"

# ============================================================
# Global Defaults
# ============================================================

workers: 20
timeout: "5s"
skip_waf: true
format: "text"
no_color: false
no_progress: false
`
}

// updateWAFDatabase updates the WAF IP ranges database
func updateWAFDatabase() error {
	wafPath := getWAFDatabasePath()
	updater, err := waf.NewUpdater("data/waf_sources.json", wafPath)
	if err != nil {
		return fmt.Errorf("failed to create updater: %w", err)
	}

	return updater.Update()
}

// generatePassiveFilename creates a filename for passive scan results
// Format: domain.com-passive-2025-12-04_14-30-45.txt
func generatePassiveFilename(domain string) string {
	return generateOutputFilename(domain, "passive")
}

// generateActiveFilename creates a filename for active scan results
// Format: domain.com-active-2025-12-04_14-30-45.txt
func generateActiveFilename(domain string) string {
	return generateOutputFilename(domain, "active")
}

// generateAutoFilename creates a filename for auto scan results
// Format: domain.com-auto-2025-12-04_14-30-45.txt
func generateAutoFilename(domain string) string {
	return generateOutputFilename(domain, "auto")
}

// generateOutputFilename creates a filename for scan results
// Format: domain.com-{mode}-2025-12-04_14-30-45.txt
func generateOutputFilename(domain, mode string) string {
	// Sanitize domain name (remove invalid filename characters)
	sanitized := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "-",
		"?", "-",
		"\"", "-",
		"<", "-",
		">", "-",
		"|", "-",
	).Replace(domain)

	// Generate timestamp: 2025-12-04_14-30-45
	timestamp := time.Now().Format("2006-01-02_15-04-05")

	return fmt.Sprintf("%s-%s-%s.txt", sanitized, mode, timestamp)
}

// expandIPToCIDR expands a single IP to its CIDR network
// Example: "192.168.1.5", "/24" -> 192.168.1.0/24 range
func expandIPToCIDR(ipAddr string, cidrSuffix string) ([2]uint32, error) {
	// Parse IP
	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil {
		return [2]uint32{}, fmt.Errorf("invalid IP: %s", ipAddr)
	}

	// Create CIDR string
	cidrStr := ipAddr + cidrSuffix // e.g., "192.168.1.5/24"

	// Parse CIDR to get network range
	ipRange, err := ip.ParseCIDRRange(cidrStr)
	if err != nil {
		return [2]uint32{}, err
	}

	return [2]uint32{ipRange.Start, ipRange.End}, nil
}

// deduplicateIPRanges removes overlapping and duplicate IP ranges
func deduplicateIPRanges(ranges [][2]uint32) [][2]uint32 {
	if len(ranges) <= 1 {
		return ranges
	}

	// Sort ranges by start IP
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i][0] < ranges[j][0]
	})

	// Merge overlapping ranges
	merged := [][2]uint32{ranges[0]}

	for i := 1; i < len(ranges); i++ {
		current := ranges[i]
		last := &merged[len(merged)-1]

		// Check if current range overlaps or is adjacent to last range
		if current[0] <= last[1]+1 {
			// Merge: extend last range if current ends later
			if current[1] > last[1] {
				last[1] = current[1]
			}
			// If current is completely contained in last, do nothing
		} else {
			// No overlap: add as new range
			merged = append(merged, current)
		}
	}

	return merged
}

// getRerunCommand generates a rerun command suggestion
func getRerunCommand(config *core.Config) string {
	cmd := "origindive -d " + config.Domain
	if config.StartIP != "" && config.EndIP != "" {
		cmd += " -s " + config.StartIP + " -e " + config.EndIP
	} else if config.CIDR != "" {
		cmd += " -n " + config.CIDR
	} else if config.InputFile != "" {
		cmd += " -i " + config.InputFile
	} else if config.ASN != "" {
		cmd += " --asn " + config.ASN
	}
	if config.SkipWAF {
		cmd += " --skip-waf"
	}
	return cmd
}

// checkDomainWAF checks if a domain's current IP is behind WAF/CDN
func checkDomainWAF(domain, wafDBPath string) (bool, string) {
	// Resolve domain to IP
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return false, ""
	}

	// Load WAF database
	db, err := waf.LoadWAFDatabase(wafDBPath)
	if err != nil {
		return false, ""
	}

	// Create range set and add all providers
	rangeSet := waf.NewRangeSet()
	for i := range db.Providers {
		rangeSet.AddProvider(&db.Providers[i])
	}

	// Check each resolved IP
	for _, ip := range ips {
		// Only check IPv4
		if ipv4 := ip.To4(); ipv4 != nil {
			if providerID, found := rangeSet.FindProvider(ipv4); found {
				// Get provider name
				if provider := db.GetProvider(providerID); provider != nil {
					return true, provider.Name
				}
				return true, providerID
			}
		}
	}

	return false, ""
}

func printBanner(config *core.Config) {
	fmt.Println()
	fmt.Printf("%s           _      _         ___         %s\n", colors.CYAN, colors.NC)
	fmt.Printf("%s ___  ____(_)__ _(_)__  ___/ (_)  _____ %s\n", colors.CYAN, colors.NC)
	fmt.Printf("%s/ _ \\/ __/ / _ `/ / _ \\/ _  / / |/ / -_)%s\n", colors.CYAN, colors.NC)
	fmt.Printf("%s\\___/_/ /_/\\_, /_/_//_/\\_,_/_/|___/\\__/ %s\n", colors.CYAN, colors.NC)
	fmt.Printf("%s          /___/                         %s\n", colors.CYAN, colors.NC)
	fmt.Println()
	fmt.Printf("%sv%s - Origin IP Discovery Tool%s\n", colors.BOLD, version.Version, colors.NC)
	if config.SkipWAF {
		fmt.Printf("%sWAF Filtering: ENABLED%s\n", colors.GREEN, colors.NC)
	}
	fmt.Printf("%s[*]%s Domain: %s\n", colors.BLUE, colors.NC, config.Domain)

	// Check if domain is behind WAF/CDN
	if behindWAF, provider := checkDomainWAF(config.Domain, config.WAFDatabasePath); behindWAF {
		fmt.Printf("%s[!]%s Domain appears to be behind %s%s%s\n", colors.YELLOW, colors.NC, colors.BOLD, provider, colors.NC)
	}

	fmt.Printf("%s[*]%s Mode: %s\n", colors.BLUE, colors.NC, config.Mode)
	fmt.Printf("%s[*]%s Workers: %d\n", colors.BLUE, colors.NC, config.Workers)
	fmt.Printf("%s[*]%s Timeout: %s\n", colors.BLUE, colors.NC, config.Timeout)
	fmt.Println()
}
