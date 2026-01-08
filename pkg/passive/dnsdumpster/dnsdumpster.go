// Package dnsdumpster provides DNSDumpster API integration for passive reconnaissance
package dnsdumpster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DNSDumpsterResponse represents the API response structure
type DNSDumpsterResponse struct {
	A      []DNSRecord `json:"a"`
	AAAA   []DNSRecord `json:"aaaa"`
	CNAME  []DNSRecord `json:"cname"`
	MX     []DNSRecord `json:"mx"`
	NS     []DNSRecord `json:"ns"`
	TXT    []string    `json:"txt"`
	TotalA int         `json:"total_a_recs"`
	Error  string      `json:"error,omitempty"`
}

// DNSRecord represents a DNS record with IPs
type DNSRecord struct {
	Host string     `json:"host"`
	IPs  []IPDetail `json:"ips"`
}

// IPDetail contains detailed IP information
type IPDetail struct {
	IP          string `json:"ip"`
	ASN         string `json:"asn"`
	ASNName     string `json:"asn_name"`
	ASNRange    string `json:"asn_range"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	PTR         string `json:"ptr"`
}

// apiBaseURL is the DNSDumpster API endpoint (can be overridden in tests)
var apiBaseURL = "https://api.dnsdumpster.com/domain/"

// SearchDomain queries DNSDumpster API for domain information
func SearchDomain(ctx context.Context, domain string, apiKeys []string, timeout time.Duration) ([]string, error) {
	if len(apiKeys) == 0 {
		return []string{}, fmt.Errorf("no DNSDumpster API keys provided")
	}

	// Try each API key until one works
	var lastErr error
	for i, apiKey := range apiKeys {
		apiKey = strings.TrimSpace(apiKey)
		if apiKey == "" {
			continue
		}

		ips, err := searchWithKey(ctx, domain, apiKey, timeout)
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

// searchWithKey performs the search with a single API key
func searchWithKey(ctx context.Context, domain, apiKey string, timeout time.Duration) ([]string, error) {
	url := fmt.Sprintf("%s%s", apiBaseURL, domain)

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// DNSDumpster uses X-API-Key header
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("User-Agent", "origindive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DNSDumpster request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		// Try to parse error from JSON
		var errResp DNSDumpsterResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("DNSDumpster API error (HTTP %d): %s", resp.StatusCode, errResp.Error)
		}

		// Truncate body for error message
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("DNSDumpster returned status %d: %s", resp.StatusCode, strings.TrimSpace(bodyStr))
	}

	// Parse successful response
	var dnsResp DNSDumpsterResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse DNSDumpster response: %w", err)
	}

	// Check for API error in JSON (even with 200 OK)
	if dnsResp.Error != "" {
		return nil, fmt.Errorf("DNSDumpster API error: %s", dnsResp.Error)
	}

	// Extract unique IPv4 addresses from all record types
	ipSet := make(map[string]bool)

	// Process A records
	for _, record := range dnsResp.A {
		for _, ipDetail := range record.IPs {
			ip := strings.TrimSpace(ipDetail.IP)
			if isValidIPv4(ip) {
				ipSet[ip] = true
			}
		}
	}

	// Process MX records
	for _, record := range dnsResp.MX {
		for _, ipDetail := range record.IPs {
			ip := strings.TrimSpace(ipDetail.IP)
			if isValidIPv4(ip) {
				ipSet[ip] = true
			}
		}
	}

	// Process NS records
	for _, record := range dnsResp.NS {
		for _, ipDetail := range record.IPs {
			ip := strings.TrimSpace(ipDetail.IP)
			if isValidIPv4(ip) {
				ipSet[ip] = true
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

// isValidIPv4 validates an IPv4 address
func isValidIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}
