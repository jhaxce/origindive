// Package scanner provides HTTP-based origin IP discovery with concurrent scanning.
package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jhaxce/origindive/v3/internal/colors"
	"github.com/jhaxce/origindive/v3/internal/version"
	"github.com/jhaxce/origindive/v3/pkg/core"
	"github.com/jhaxce/origindive/v3/pkg/ip"
	"github.com/jhaxce/origindive/v3/pkg/output"
	"github.com/jhaxce/origindive/v3/pkg/proxy"
	"github.com/jhaxce/origindive/v3/pkg/waf"
)

// Scanner performs HTTP-based origin IP discovery
type Scanner struct {
	config           *core.Config
	client           *http.Client
	wafFilter        *waf.Filter
	proxyList        []*proxy.Proxy // List of proxies for rotation
	proxyIndex       uint64         // Atomic counter for proxy rotation
	mu               sync.Mutex
	cancelFunc       context.CancelFunc
	progressCallback func(scanned, total uint64) // Progress update callback
	resultCallback   func(result *core.IPResult) // Real-time result callback
	progressStopper  func()                      // Function to stop progress display
}

// New creates a new scanner with the given configuration
func New(config *core.Config) (*Scanner, error) {
	if config == nil {
		return nil, core.ErrInvalidConfig
	}

	var proxyClient *http.Client
	var proxyList []*proxy.Proxy

	// Handle proxy configuration
	if config.ProxyAuto {
		// Auto-fetch proxies from public lists
		fmt.Println("[*] Fetching proxies from public sources...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Configure Webshare if API key is provided
		var webshareConfig *proxy.WebshareConfig
		if config.WebshareAPIKey != "" {
			webshareConfig = &proxy.WebshareConfig{
				APIKey: config.WebshareAPIKey,
				PlanID: config.WebsharePlanID,
			}
		}

		proxies, err := proxy.FetchProxyList(ctx, nil, webshareConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch proxy list: %w", err)
		}
		fmt.Printf("[*] Fetched %d proxies from public sources\n", len(proxies))

		if config.ProxyTest {
			// Validate proxies (keep only working ones)
			fmt.Println("[*] Validating proxies (this may take a moment)...")

			// Smart sampling for large proxy lists (>1000 proxies)
			proxyCount := len(proxies)
			if proxyCount > 1000 {
				// Sample 20% of proxies, up to 2000 max
				sampleSize := proxyCount / 5
				if sampleSize > 2000 {
					sampleSize = 2000
				}

				fmt.Printf("[*] Sampling %d out of %d proxies for validation...\n", sampleSize, proxyCount)

				// IMPORTANT: Always include first proxies (Webshare premium are first)
				// This prevents premium proxies from being randomly excluded
				sampled := make([]*proxy.Proxy, 0, sampleSize)

				// Take first 50 proxies (likely Webshare + some free)
				guaranteed := 50
				if proxyCount < guaranteed {
					guaranteed = proxyCount
				}
				sampled = append(sampled, proxies[:guaranteed]...)

				// Random sample from the rest
				remaining := sampleSize - guaranteed
				if remaining > 0 && proxyCount > guaranteed {
					for i := 0; i < remaining; i++ {
						idx := guaranteed + rand.Intn(proxyCount-guaranteed)
						sampled = append(sampled, proxies[idx])
					}
				}

				proxies = proxy.ValidateProxies(ctx, sampled, 3*time.Second, 50)
			} else {
				// Validate all proxies with more workers
				proxies = proxy.ValidateProxies(ctx, proxies, 5*time.Second, 50)
			}

			if len(proxies) == 0 {
				return nil, fmt.Errorf("no working proxies found after validation")
			}
			fmt.Printf("[+] %d working proxies validated\n\n", len(proxies))
		}

		proxyList = proxies
		// Use first proxy for initial client
		proxyClient, _ = proxies[0].GetHTTPClient(config.Timeout)
		if config.ProxyRotate {
			fmt.Println("[*] Proxy rotation enabled")
		}

	} else if config.ProxyURL != "" {
		// Use specified proxy
		fmt.Printf("[*] Using proxy: %s\n", config.ProxyURL)
		proxyObj, err := proxy.ParseProxy(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
		}

		if config.ProxyTest {
			// Test proxy before use
			fmt.Println("[*] Testing proxy...")
			if err := proxyObj.TestProxy(5 * time.Second); err != nil {
				return nil, fmt.Errorf("proxy test failed: %w", err)
			}
			fmt.Println("[+] Proxy test successful")
		}

		proxyClient, err = proxyObj.GetHTTPClient(config.Timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy client: %w", err)
		}

		if config.ProxyRotate {
			// Single proxy but add to list for compatibility
			proxyList = []*proxy.Proxy{proxyObj}
		}
	}

	// Create HTTP client (with or without proxy)
	var client *http.Client
	if proxyClient != nil {
		client = proxyClient
	} else {
		// Standard client without proxy
		client = &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: config.ConnectTimeout,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Required for testing origin servers
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: config.Workers,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}
	}

	s := &Scanner{
		config:    config,
		client:    client,
		proxyList: proxyList,
	}

	// Load WAF filter if enabled and database path is set
	if config.SkipWAF {
		wafPath := config.WAFDatabasePath
		if wafPath == "" {
			wafPath = "data/waf_ranges.json" // Default path
		}

		// Only load if we can access the file (handles test case with empty path)
		db, err := waf.LoadWAFDatabase(wafPath)
		if err != nil {
			// If using default path and it doesn't exist, silently skip
			// If using custom path, this is an error
			if config.WAFDatabasePath != "" {
				return nil, fmt.Errorf("failed to load WAF database from %s: %w", wafPath, err)
			}
			// Default path not found - continue without WAF filtering
		} else {
			filter, err := waf.NewFilterFromDatabase(db, config.SkipProviders, config.ShowSkipped)
			if err != nil {
				return nil, fmt.Errorf("failed to create WAF filter: %w", err)
			}
			s.wafFilter = filter
		}
	}

	return s, nil
}

// Scan performs the HTTP scanning across the configured IP ranges
func (s *Scanner) Scan(ctx context.Context) (*core.ScanResult, error) {
	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel
	defer cancel()

	result := &core.ScanResult{
		Domain:    s.config.Domain,
		Mode:      s.config.Mode,
		StartTime: time.Now(),
	}

	// Calculate total IPs
	// Convert [][2]uint32 from config to []ip.IPRange
	ranges := make([]ip.IPRange, len(s.config.IPRanges))
	for i, r := range s.config.IPRanges {
		ranges[i] = ip.IPRange{Start: r[0], End: r[1]}
	}

	iterator := ip.NewIterator(ranges)
	totalIPs := iterator.TotalIPs()
	if totalIPs == 0 {
		return nil, fmt.Errorf("no IP ranges to scan")
	}

	// Create channels
	jobs := make(chan uint32, s.config.Workers*2)
	results := make(chan *core.IPResult, s.config.Workers*2)

	// Atomic counters
	var (
		scanned uint64
		skipped uint64
	)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, jobs, results, &scanned, &skipped)
	}

	// Result collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for ipResult := range results {
			result.AddResult(ipResult)
		}
	}()

	// Feed jobs
	go func() {
		defer close(jobs)
		for {
			ipInt, ok := iterator.NextUint32()
			if !ok {
				break
			}

			select {
			case jobs <- ipInt:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for workers
	wg.Wait()
	close(results)

	// Wait for collector
	collectorWg.Wait()

	// Validate successful IPs if both --verify and --follow-redirect are enabled
	// This checks if IPs behave the same without Host header (detects shared hosting)
	if s.config.VerifyContent && s.config.MaxRedirects > 0 && len(result.Success) > 0 {
		// Stop progress bar before validation to prevent double display
		if s.progressStopper != nil {
			s.progressStopper()
			time.Sleep(150 * time.Millisecond) // Let display goroutine finish
			fmt.Println()                      // Blank line after progress bar
		}

		// Colorize verification header if colors are initialized
		if !s.config.NoColor {
			fmt.Println(colors.YELLOW + "[*] Verifying redirect behavior" + colors.NC + "\n")
		} else {
			fmt.Print("[*] Verifying redirect behavior\n\n")
		}
		falsePositiveIPs := s.validateSuccessfulIPs(ctx, result.Success)
		// Additionally perform PTR reverse lookup checks
		ptrFalsePos := s.validatePTRs(ctx, result.Success)
		// Merge PTR false positives into overall list
		if len(ptrFalsePos) > 0 {
			falsePositiveIPs = append(falsePositiveIPs, ptrFalsePos...)
		}
		if len(falsePositiveIPs) > 0 {
			result.Summary.FalsePositiveCount = uint64(len(falsePositiveIPs))
			result.Summary.FalsePositiveIPs = falsePositiveIPs
		}

		// Collect possible origin IPs from success results and classify as related vs other
		related := make([]string, 0)
		other := make([]string, 0)
		for _, r := range result.Success {
			if r.PossibleOrigin {
				// Classify as related if the recorded destination contains the configured domain
				if strings.Contains(strings.ToLower(r.PossibleOriginDest), strings.ToLower(s.config.Domain)) {
					related = append(related, r.IP)
				} else {
					other = append(other, r.IP)
				}
			} else {
				// Fallback: check redirect chain notes for legacy "Possible origin IP" note
				for _, note := range r.RedirectChain {
					if strings.HasPrefix(note, "Possible origin IP:") {
						// Treat as other by default
						other = append(other, r.IP)
						break
					}
				}
			}
		}

		total := len(related) + len(other)
		if total > 0 {
			result.Summary.PossibleOriginCount = uint64(total)
			// Combine related then other for predictable ordering
			combined := make([]string, 0, total)
			combined = append(combined, related...)
			combined = append(combined, other...)
			result.Summary.PossibleOriginIPs = combined
			result.Summary.PossibleOriginRelatedCount = uint64(len(related))
			result.Summary.PossibleOriginRelatedIPs = related
		}
	}

	// Finalize result
	result.EndTime = time.Now()
	result.Summary.TotalIPs = totalIPs
	result.Summary.ScannedIPs = scanned
	result.Summary.SkippedIPs = skipped
	result.Summary.SuccessCount = uint64(len(result.Success))
	result.Summary.Duration = result.EndTime.Sub(result.StartTime)

	// Extract success IPs for summary display
	result.Summary.SuccessIPs = make([]string, 0, len(result.Success))
	for _, ipResult := range result.Success {
		result.Summary.SuccessIPs = append(result.Summary.SuccessIPs, ipResult.IP)
	}

	// Add WAF stats if filter was used
	if s.wafFilter != nil {
		stats := s.wafFilter.GetStats()
		result.Summary.WAFStats = stats.ByProvider
	}

	return result, nil
}

// worker processes IP addresses from the jobs channel
func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan uint32, results chan<- *core.IPResult, scanned, skipped *uint64) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ipInt, ok := <-jobs:
			if !ok {
				return
			}

			// Convert to net.IP
			ipAddr := ip.FromUint32(ipInt)

			// Check WAF filter
			if s.wafFilter != nil {
				shouldSkip, provider := s.wafFilter.ShouldSkip(ipAddr)
				if shouldSkip {
					newSkipped := atomic.AddUint64(skipped, 1)

					// Update progress
					if s.progressCallback != nil {
						s.progressCallback(atomic.LoadUint64(scanned)+newSkipped, 0)
					}

					if s.config.ShowSkipped {
						results <- &core.IPResult{
							IP:       ipAddr.String(),
							Status:   "skipped",
							Provider: provider,
						}
					}
					continue
				}
			}

			// Scan the IP
			result := s.scanIP(ctx, ipAddr)
			newScanned := atomic.AddUint64(scanned, 1)

			// Update progress
			if s.progressCallback != nil {
				s.progressCallback(newScanned+atomic.LoadUint64(skipped), 0)
			}

			// Send result
			if s.config.ShowAll || result.Status == "200" {
				// Call result callback for real-time display
				if s.resultCallback != nil {
					s.resultCallback(result)
				}
				results <- result
			}
		}
	}
}

// scanIP performs HTTP request to a single IP
func (s *Scanner) scanIP(ctx context.Context, ipAddr net.IP) *core.IPResult {
	result := &core.IPResult{
		IP: ipAddr.String(),
	}

	// Construct URL
	url := fmt.Sprintf("http://%s", ipAddr.String())

	// Create request
	req, err := http.NewRequestWithContext(ctx, s.config.HTTPMethod, url, nil)
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result
	}

	// Set Host header
	req.Host = s.config.Domain

	// Set User-Agent
	if !s.config.NoUserAgent {
		userAgent := s.getUserAgent()
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
	}

	// Set custom header if specified
	if s.config.CustomHeader != "" {
		// Parse header (format: "Name: Value")
		// Simple implementation - just set as-is
		req.Header.Set("X-Custom", s.config.CustomHeader)
	}

	// Perform request
	startTime := time.Now()
	client := s.getClient() // Use proxy-aware client

	// If redirect following is enabled, first check natural redirect (without Host header)
	// This helps detect shared hosting where Host header influences redirect destination
	var naturalRedirect string
	if s.config.MaxRedirects > 0 {
		testReq, _ := http.NewRequestWithContext(ctx, s.config.HTTPMethod, url, nil)
		testClient := &http.Client{
			Transport: client.Transport,
			Timeout:   client.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow, just capture first redirect
			},
		}
		testResp, err := testClient.Do(testReq)
		if err == nil {
			defer testResp.Body.Close()
			if testResp.StatusCode >= 300 && testResp.StatusCode < 400 {
				naturalRedirect = testResp.Header.Get("Location")
			}
		}
	}

	// Handle redirects if enabled
	var redirectChain []string
	var customClient *http.Client
	if s.config.MaxRedirects > 0 {
		// Create a custom client with redirect tracking
		initialURL := url
		originalIP := ipAddr.String()
		targetDomain := s.config.Domain

		customClient = &http.Client{
			Transport: client.Transport,
			Timeout:   client.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Record each redirect hop
				if len(via) > 0 {
					prevReq := via[len(via)-1]
					statusCode := 301 // Default
					if prevReq.Response != nil {
						statusCode = prevReq.Response.StatusCode
					}
					hopInfo := fmt.Sprintf("%d %s -> %s", statusCode, prevReq.URL.String(), req.URL.String())
					redirectChain = append(redirectChain, hopInfo)

					// Check if first redirect points to target domain
					// If it redirects to the IP itself or a different domain, it's not a real origin
					redirectHost := req.URL.Host
					// Remove port from host for comparison
					if idx := strings.Index(redirectHost, ":"); idx > 0 {
						redirectHost = redirectHost[:idx]
					}

					// If we have a natural redirect that differs from the current redirect location,
					// validate that the natural redirect also contains the target domain
					if len(via) == 1 && naturalRedirect != "" {
						// Parse natural redirect URL to extract host
						naturalHost := naturalRedirect
						if strings.HasPrefix(naturalHost, "http://") {
							naturalHost = naturalHost[7:]
						} else if strings.HasPrefix(naturalHost, "https://") {
							naturalHost = naturalHost[8:]
						}
						// If hostname has a leading www., strip it for comparison
						if idx := strings.Index(naturalHost, "www."); idx > 0 {
							naturalHost = naturalHost[4:]
						}
						// Extract just the hostname part
						if idx := strings.Index(naturalHost, "/"); idx > 0 {
							naturalHost = naturalHost[:idx]
						}
						if idx := strings.Index(naturalHost, ":"); idx > 0 {
							naturalHost = naturalHost[:idx]
						}

						// If natural redirect doesn't contain target domain, this is shared hosting
						if !strings.Contains(naturalHost, targetDomain) && naturalHost != originalIP {
							// Natural redirect points elsewhere - stop following
							return http.ErrUseLastResponse
						}
					}

					// If first redirect doesn't contain target domain, stop following
					if len(via) == 1 && !strings.Contains(redirectHost, targetDomain) {
						// First redirect doesn't point to target domain - this is shared hosting
						// Don't follow further redirects
						return http.ErrUseLastResponse
					}

					// Rewrite redirect URL to keep testing the same IP
					// Instead of following redirect to new domain, rewrite URL to use original IP
					redirectedDomain := req.URL.Host
					req.URL.Host = originalIP
					req.Host = redirectedDomain // Keep Host header as redirected domain
					// Remove Referer to avoid leaking the original IP in redirected requests
					req.Header.Del("Referer")
				}

				// Check if we've exceeded the max redirects
				if len(via) >= s.config.MaxRedirects {
					return fmt.Errorf("stopped after %d redirects", s.config.MaxRedirects)
				}

				return nil
			},
		}
		resp, err := customClient.Do(req)
		result.ResponseTime = time.Since(startTime).String()

		if err != nil {
			// Check for timeout
			if ctx.Err() == context.DeadlineExceeded {
				result.Status = "timeout"
			} else {
				result.Status = "error"
				result.Error = err.Error()
			}
			return result
		}
		defer resp.Body.Close()

		// Record response and redirect chain
		result.HTTPCode = resp.StatusCode
		result.Server = resp.Header.Get("Server")
		result.ContentType = resp.Header.Get("Content-Type")

		// If final URL differs from initial URL, add a redirect note
		finalURL := resp.Request.URL.String()
		if finalURL != initialURL && len(redirectChain) == 0 {
			// Automatic redirect (e.g., HTTP -> HTTPS or path change by Transport)
			redirectChain = append(redirectChain, fmt.Sprintf("(automatic) %s -> %s", initialURL, finalURL))
		}
		result.RedirectChain = redirectChain

		// Extract content if enabled and status is 200
		if s.config.VerifyContent && resp.StatusCode == 200 {
			// Read response body (limit to 64KB for safety)
			body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			if err == nil {
				// Calculate SHA256 hash
				hash := sha256.Sum256(body)
				result.BodyHash = hex.EncodeToString(hash[:])[:16] // First 16 chars

				// Extract HTML title if Content-Type is HTML
				if strings.Contains(strings.ToLower(result.ContentType), "html") {
					result.Title = extractTitle(string(body))
				}
			}
		}

		switch {
		case resp.StatusCode == 200:
			result.Status = "200"
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			result.Status = "3xx"
		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			result.Status = "4xx"
		case resp.StatusCode >= 500:
			result.Status = "5xx"
		default:
			result.Status = fmt.Sprintf("%d", resp.StatusCode)
		}

		return result
	}

	// Standard request without redirect tracking
	resp, err := client.Do(req)
	result.ResponseTime = time.Since(startTime).String()

	if err != nil {
		// Check for timeout
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
		} else {
			result.Status = "error"
			result.Error = err.Error()
		}
		return result
	}
	defer resp.Body.Close()

	// Record response
	result.HTTPCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")
	result.ContentType = resp.Header.Get("Content-Type")

	// Extract content if enabled and status is 200
	if s.config.VerifyContent && resp.StatusCode == 200 {
		// Read response body (limit to 64KB for safety)
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err == nil {
			// Calculate SHA256 hash
			hash := sha256.Sum256(body)
			result.BodyHash = hex.EncodeToString(hash[:])[:16] // First 16 chars

			// Extract HTML title if Content-Type is HTML
			if strings.Contains(strings.ToLower(result.ContentType), "html") {
				result.Title = extractTitle(string(body))
			}
		}
	}

	switch {
	case resp.StatusCode == 200:
		result.Status = "200"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		result.Status = "3xx"
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		result.Status = "4xx"
	case resp.StatusCode >= 500:
		result.Status = "5xx"
	default:
		result.Status = fmt.Sprintf("%d", resp.StatusCode)
	}

	return result
}

// extractTitle extracts the <title> tag content from HTML
func extractTitle(html string) string {
	// Simple regex to extract title (not perfect but good enough)
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Limit title length
		if len(title) > 100 {
			title = title[:97] + "..."
		}
		return title
	}
	return ""
}

// Stop cancels the ongoing scan
func (s *Scanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancelFunc != nil {
		s.cancelFunc()
	}
}

// SetProgressCallback sets a callback function for progress updates
func (s *Scanner) SetProgressCallback(callback func(scanned, total uint64)) {
	s.progressCallback = callback
}

// SetProgressStopper sets a function to stop progress display
func (s *Scanner) SetProgressStopper(stopper func()) {
	s.progressStopper = stopper
}

// SetResultCallback sets a callback for real-time result streaming
func (s *Scanner) SetResultCallback(callback func(result *core.IPResult)) {
	s.resultCallback = callback
}

// validateSuccessfulIPs checks if successful IPs behave the same without Host header
// This helps detect shared hosting where the Host header influences the response
// Returns list of IPs flagged as potential false positives
func (s *Scanner) validateSuccessfulIPs(ctx context.Context, successIPs []*core.IPResult) []string {
	// Follow redirects up to max, preserving IP like main scan but without Host header
	var naturalChain []string
	falsePositiveIPs := make([]string, 0)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: s.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= s.config.MaxRedirects {
				return http.ErrUseLastResponse
			}

			// Capture redirect in chain
			redirectURL := req.URL.String()
			statusCode := 301
			if len(via) > 0 {
				lastResp := via[len(via)-1].Response
				if lastResp != nil {
					statusCode = lastResp.StatusCode
				}
			}
			entry := fmt.Sprintf("%d %s -> %s", statusCode, via[len(via)-1].URL.String(), redirectURL)
			naturalChain = append(naturalChain, entry)

			// Preserve IP: rewrite URL to use original IP, but don't set Host header
			originalIP := via[0].URL.Host
			req.URL.Host = originalIP
			// DON'T set req.Host - that's the key difference from main scan
			// Remove Referer to avoid leaking the previous destination/IP
			req.Header.Del("Referer")

			return nil
		},
	}

	// Optional progress bar for verification pass
	var prog *output.Progress
	showProg := !s.config.NoProgress && !s.config.Quiet
	if showProg {
		total := uint64(len(successIPs))
		prog = output.NewProgress(total, true, !s.config.NoColor)
		go prog.Display()
	}

	for idx, ipResult := range successIPs {
		// Update progress if shown
		if showProg && prog != nil {
			prog.Update(uint64(idx + 1))
		}
		// If no redirect chain (direct 200 OK), still verify content without Host header
		if len(ipResult.RedirectChain) == 0 {
			if ipResult.Status == "200" && ipResult.BodyHash != "" {
				// Test without Host header and compare body hash
				testURL := fmt.Sprintf("http://%s", ipResult.IP)
				testReq, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
				if err == nil {
					resp2, err2 := client.Do(testReq)
					if err2 == nil {
						// Read body and compute hash (limit to 64KB as in scanIP)
						body, errRead := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
						resp2.Body.Close()
						if errRead == nil {
							h := sha256.Sum256(body)
							hashStr := hex.EncodeToString(h[:])[:16]
							if hashStr == ipResult.BodyHash {
								originNote := fmt.Sprintf("Possible origin IP (Unrelated): %s (content match)", ipResult.IP)
								ipResult.RedirectChain = append(ipResult.RedirectChain, originNote)
								ipResult.PossibleOrigin = true
								ipResult.PossibleOriginDest = ""
							} else {
								note := fmt.Sprintf("Note: Without Host header: content differs from Host-based response (but still possible)")
								ipResult.RedirectChain = append(ipResult.RedirectChain, note)
								// Treat ambiguous 'Note' cases as related possible origins
								// Add grab the value if the domain has waf then approve thiss line
								// ipResult.PossibleOrigin = true
								// ipResult.PossibleOriginDest = s.config.Domain
							}
						}
					}
				}
			}
			continue
		}

		// Reset natural chain for this IP
		naturalChain = []string{}

		// Test without Host header
		url := fmt.Sprintf("http://%s", ipResult.IP)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		// Don't set Host header - let it default to the IP
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Compare natural chain vs Host-header chain
		if len(naturalChain) > 0 {
			// Extract final destination from both chains
			lastNatural := naturalChain[len(naturalChain)-1]
			lastWithHost := ipResult.RedirectChain[len(ipResult.RedirectChain)-1]

			// Parse final destinations
			var naturalDest, hostDest string
			if parts := strings.Split(lastNatural, " -> "); len(parts) == 2 {
				naturalDest = strings.TrimSpace(parts[1])
			}
			if parts := strings.Split(lastWithHost, " -> "); len(parts) == 2 {
				hostDest = strings.TrimSpace(parts[1])
			}

			// Compare destinations (normalize to ignore default ports)
			if naturalDest != "" && hostDest != "" {
				// Normalize for comparison (strip default ports and normalize path)
				normNatural := normalizeURLForCompare(naturalDest)
				normHost := normalizeURLForCompare(hostDest)

				if normNatural != normHost {
					natHost := extractHost(naturalDest)
					hostDestHost := extractHost(hostDest)

					displayNatural := normalizeURLForDisplay(naturalDest)
					displayHost := normalizeURLForDisplay(hostDest)

					// If hosts differ and natural doesn't contain the target domain and isn't raw IP, flag as false-positive
					if natHost != hostDestHost && !strings.Contains(strings.ToLower(naturalDest), strings.ToLower(s.config.Domain)) && natHost != ipResult.IP {
						warning := fmt.Sprintf("⚠ Without Host header: %s (different from %s)", displayNatural, displayHost)
						ipResult.RedirectChain = append(ipResult.RedirectChain, warning)
						falsePositiveIPs = append(falsePositiveIPs, ipResult.IP)
					} else {
						note := fmt.Sprintf("Note: Without Host header: %s (different from %s)", displayNatural, displayHost)
						ipResult.RedirectChain = append(ipResult.RedirectChain, note)
					}
				}
				// If normalized values are equal, this is a good signal the IP may be the origin server.
				if normNatural == normHost {
					display := normalizeURLForDisplay(naturalDest)
					originNote := fmt.Sprintf("Possible origin IP: %s (destination: %s)", ipResult.IP, display)
					ipResult.RedirectChain = append(ipResult.RedirectChain, originNote)

					// Mark as possible origin and record the destination for later classification
					ipResult.PossibleOrigin = true
					ipResult.PossibleOriginDest = display
				}
			}
		}
	}

	// Stop progress bar if active
	if prog != nil {
		prog.Stop()
		time.Sleep(100 * time.Millisecond)
		if !s.config.Quiet {
			fmt.Println()
		}
	}
	return falsePositiveIPs
}

// normalizeURLForCompare parses a URL and returns a normalized string
// without default ports so that https://host:443/... and https://host/... compare equal.
func normalizeURLForCompare(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		// Fallback to raw string
		return strings.TrimSuffix(u, "/")
	}
	host := parsed.Hostname()
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s://%s%s", parsed.Scheme, host, path)
}

// normalizeURLForDisplay returns a cleaned URL string suitable for user-facing notes
// It strips default ports and preserves the path.
func normalizeURLForDisplay(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	host := parsed.Hostname()
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s://%s%s", parsed.Scheme, host, path)
}

// validatePTRs performs reverse DNS (PTR) lookups for successful IPs.
// It populates IPResult.PTR and returns a list of IPs considered potential false-positives
// when the PTR record clearly points to a different host (not containing the target domain).
func (s *Scanner) validatePTRs(ctx context.Context, successIPs []*core.IPResult) []string {
	falsePositiveIPs := make([]string, 0)

	for _, ipResult := range successIPs {
		// perform lookup with per-lookup timeout
		lookupCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
		names, err := net.DefaultResolver.LookupAddr(lookupCtx, ipResult.IP)
		cancel()
		if err != nil || len(names) == 0 {
			// No PTR found; record empty PTR
			ipResult.PTR = ""
			continue
		}

		// join names
		// strip trailing dot from PTR names
		for i, n := range names {
			names[i] = strings.TrimSuffix(n, ".")
		}
		ipResult.PTR = strings.Join(names, ", ")

		// If PTR does not contain the configured domain, flag for review
		ptrLower := strings.ToLower(ipResult.PTR)
		domainLower := strings.ToLower(s.config.Domain)
		if !strings.Contains(ptrLower, domainLower) {
			warning := fmt.Sprintf("⚠ PTR: reverse DNS points to %s", ipResult.PTR)
			ipResult.RedirectChain = append(ipResult.RedirectChain, warning)
			falsePositiveIPs = append(falsePositiveIPs, ipResult.IP)
		}
	}

	return falsePositiveIPs
}

// extractHost extracts hostname from a URL string
func extractHost(urlStr string) string {
	host := urlStr
	// Remove protocol
	if idx := strings.Index(host, "://"); idx > 0 {
		host = host[idx+3:]
	}
	// Strip leading www. for normalized comparisons
	if idx := strings.Index(host, "://"); idx > 0 {
		host = host[idx+4:]
	}
	// Remove path
	if idx := strings.Index(host, "/"); idx > 0 {
		host = host[:idx]
	}
	// Remove port
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

// extractPath extracts path from a URL string
func extractPath(urlStr string) string {
	// Remove protocol
	path := urlStr
	if idx := strings.Index(path, "://"); idx > 0 {
		path = path[idx+3:]
	}
	// Find path start
	if idx := strings.Index(path, "/"); idx > 0 {
		return path[idx:]
	}
	return "/"
}

// getUserAgent returns the user agent string based on config
func (s *Scanner) getUserAgent() string {
	ua := s.config.UserAgent

	// Empty or "default" = use origindive default
	if ua == "" || ua == "default" {
		return fmt.Sprintf("origindive/%s", version.Version)
	}

	// "random" = random from all browsers
	if ua == "random" {
		return GetRandomUserAgent()
	}

	// Check if it's a browser name (chrome, firefox, safari, edge, opera, brave, mobile)
	if browserUA := GetUserAgentByBrowser(ua); browserUA != "" {
		return browserUA
	}

	// Check if it's a specific UA name (chrome-windows, firefox-mac, etc.)
	if specificUA := GetUserAgentByName(ua); specificUA != "" {
		return specificUA
	}

	// Otherwise treat as custom user agent string
	return ua
}

// getClient returns the HTTP client to use (with proxy rotation if enabled)
func (s *Scanner) getClient() *http.Client {
	// No proxy rotation needed
	if !s.config.ProxyRotate || len(s.proxyList) <= 1 {
		return s.client
	}

	// Rotate through proxy list
	index := atomic.AddUint64(&s.proxyIndex, 1) % uint64(len(s.proxyList))
	proxyObj := s.proxyList[index]

	// Create client for this proxy
	client, err := proxyObj.GetHTTPClient(s.config.Timeout)
	if err != nil {
		// Fallback to default client on error
		return s.client
	}

	return client
}
