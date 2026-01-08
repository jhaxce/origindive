// Package virustotal provides VirusTotal API v3 integration for passive reconnaissance
package virustotal

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

// VTSubdomainResponse represents the VirusTotal subdomains API response
type VTSubdomainResponse struct {
	Data  []VTDomainData `json:"data"`
	Links VTLinks        `json:"links"`
	Error VTError        `json:"error,omitempty"`
}

// VTDomainData represents a single subdomain entry
type VTDomainData struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Attributes VTDomainAttributes `json:"attributes"`
}

// VTDomainAttributes contains domain metadata
type VTDomainAttributes struct {
	LastDNSRecords []VTDNSRecord `json:"last_dns_records"`
}

// VTDNSRecord represents a DNS record
type VTDNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// VTLinks contains pagination links
type VTLinks struct {
	Self string `json:"self"`
	Next string `json:"next,omitempty"`
}

// VTError represents an API error
type VTError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// SearchSubdomains queries VirusTotal for subdomains and their DNS records
func SearchSubdomains(ctx context.Context, domain string, apiKeys []string, timeout time.Duration) ([]string, error) {
	if len(apiKeys) == 0 {
		return []string{}, fmt.Errorf("no VirusTotal API keys provided")
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

		// Check for rate limit errors (204 or 429)
		if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "204") {
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

// apiBaseURL is the VirusTotal API endpoint (can be overridden in tests)
var apiBaseURL = "https://www.virustotal.com/api/v3/domains/"

// searchWithKey performs the search with a single API key
func searchWithKey(ctx context.Context, domain, apiKey string, timeout time.Duration) ([]string, error) {
	url := fmt.Sprintf("%s%s/subdomains?limit=40", apiBaseURL, domain)

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// VirusTotal uses x-apikey header
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("User-Agent", "origindive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VirusTotal request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for rate limiting (204 No Content or 429)
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded (HTTP %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		// Try to parse error from JSON
		var errResp VTSubdomainResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("VirusTotal API error (HTTP %d): %s", resp.StatusCode, errResp.Error.Message)
		}

		// Truncate body for error message
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("VirusTotal returned status %d: %s", resp.StatusCode, strings.TrimSpace(bodyStr))
	}

	// Parse successful response
	var vtResp VTSubdomainResponse
	if err := json.Unmarshal(body, &vtResp); err != nil {
		return nil, fmt.Errorf("failed to parse VirusTotal response: %w", err)
	}

	// Check for API error in JSON (even with 200 OK)
	if vtResp.Error.Message != "" {
		return nil, fmt.Errorf("VirusTotal API error: %s", vtResp.Error.Message)
	}

	// Extract unique IPv4 addresses from DNS records
	ipSet := make(map[string]bool)
	for _, data := range vtResp.Data {
		for _, dnsRecord := range data.Attributes.LastDNSRecords {
			// Only process A records (IPv4)
			if strings.ToUpper(dnsRecord.Type) != "A" {
				continue
			}

			ip := strings.TrimSpace(dnsRecord.Value)
			if ip == "" {
				continue
			}

			// Validate IPv4
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() != nil {
				ipSet[ip] = true
			}
		}

		// Also resolve the subdomain itself
		subdomain := data.ID
		if subdomain != "" {
			// Resolve with short timeout to avoid delays
			resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			addrs, err := net.DefaultResolver.LookupHost(resolveCtx, subdomain)
			cancel()

			if err == nil {
				for _, addr := range addrs {
					parsedIP := net.ParseIP(addr)
					if parsedIP != nil && parsedIP.To4() != nil {
						ipSet[addr] = true
					}
				}
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
