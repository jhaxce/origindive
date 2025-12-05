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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jhaxce/origindive/internal/version"
	"github.com/jhaxce/origindive/pkg/core"
	"github.com/jhaxce/origindive/pkg/ip"
	"github.com/jhaxce/origindive/pkg/proxy"
	"github.com/jhaxce/origindive/pkg/waf"
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

// SetResultCallback sets a callback for real-time result streaming
func (s *Scanner) SetResultCallback(callback func(result *core.IPResult)) {
	s.resultCallback = callback
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
