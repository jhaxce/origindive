// Package viewdns provides ViewDNS.info API integration for passive reconnaissance
package viewdns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ViewDNSResponse represents the ViewDNS API response for reverse IP lookup
type ViewDNSResponse struct {
	Query    ViewDNSQuery   `json:"query"`
	Response ViewDNSResults `json:"response"`
}

// ViewDNSQuery contains the query parameters
type ViewDNSQuery struct {
	ToolType int    `json:"tool_type"`
	Host     string `json:"host"`
}

// ViewDNSResults contains the results
type ViewDNSResults struct {
	Domains []ViewDNSDomain `json:"domains"`
	Error   string          `json:"error,omitempty"`
}

// ViewDNSDomain represents a single domain on the same IP
type ViewDNSDomain struct {
	Name         string `json:"name"`
	LastResolved string `json:"last_resolved"`
}

// apiBaseURL is the ViewDNS API endpoint (can be overridden in tests)
var apiBaseURL = "https://api.viewdns.info/reverseip/"

// SearchReverseIP queries ViewDNS reverse IP lookup for domains on the same server
func SearchReverseIP(ctx context.Context, domain string, apiKeys []string, timeout time.Duration) ([]string, error) {
	if len(apiKeys) == 0 {
		return []string{}, fmt.Errorf("no ViewDNS API keys provided")
	}

	// First resolve the domain to get its current IP
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return []string{}, fmt.Errorf("failed to resolve domain: %w", err)
	}

	if len(addrs) == 0 {
		return []string{}, fmt.Errorf("no IP addresses found for domain")
	}

	// Use the first IPv4 address
	var targetIP string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && ip.To4() != nil {
			targetIP = addr
			break
		}
	}

	if targetIP == "" {
		return []string{}, fmt.Errorf("no IPv4 address found for domain")
	}

	// Try each API key until one works
	var lastErr error
	for i, apiKey := range apiKeys {
		apiKey = strings.TrimSpace(apiKey)
		if apiKey == "" {
			continue
		}

		ips, err := reverseIPWithKey(ctx, targetIP, apiKey, timeout)
		if err == nil {
			return ips, nil
		}

		// Check for rate limit errors
		if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "429") {
			lastErr = fmt.Errorf("key %d/%d rate limited: %w", i+1, len(apiKeys), err)
			continue // Try next key
		}

		// For other errors, return immediately
		return []string{}, fmt.Errorf("key %d/%d failed: %w", i+1, len(apiKeys), err)
	}

	if lastErr != nil {
		return []string{}, fmt.Errorf("all %d API keys exhausted: %w", len(apiKeys), lastErr)
	}

	return []string{}, fmt.Errorf("no valid API keys found")
}

// reverseIPWithKey performs reverse IP lookup with a single API key
func reverseIPWithKey(ctx context.Context, ipAddr, apiKey string, timeout time.Duration) ([]string, error) {
	apiURL := fmt.Sprintf("%s?host=%s&apikey=%s&output=json",
		apiBaseURL, url.QueryEscape(ipAddr), url.QueryEscape(apiKey))

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "origindive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ViewDNS request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("ViewDNS returned status %d: %s", resp.StatusCode, strings.TrimSpace(bodyStr))
	}

	// Parse JSON response
	var vdnsResp ViewDNSResponse
	if err := json.Unmarshal(body, &vdnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse ViewDNS response: %w", err)
	}

	// Check for API error
	if vdnsResp.Response.Error != "" {
		return nil, fmt.Errorf("ViewDNS API error: %s", vdnsResp.Response.Error)
	}

	// Resolve discovered domains to IPs
	ipSet := make(map[string]bool)
	resolver := &net.Resolver{}

	for _, domainEntry := range vdnsResp.Response.Domains {
		domainName := strings.TrimSpace(domainEntry.Name)
		if domainName == "" {
			continue
		}

		// Resolve with short timeout
		resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := resolver.LookupHost(resolveCtx, domainName)
		cancel()

		if err != nil {
			continue // Skip failed resolutions
		}

		// Filter IPv4 only
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip != nil && ip.To4() != nil {
				ipSet[addr] = true
			}
		}
	}

	// Convert to slice
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, nil
}
