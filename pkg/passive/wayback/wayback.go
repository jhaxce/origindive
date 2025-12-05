// Package wayback provides Internet Archive Wayback Machine CDX API integration
package wayback

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

// CDXRecord represents a single record from the Wayback Machine CDX API
type CDXRecord []string

// SearchSubdomains queries the Wayback Machine CDX API for historical subdomains
func SearchSubdomains(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	// Build URL: query for *.domain.com with JSON output and collapse by urlkey
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s&output=json&collapse=urlkey&fl=original", domain)

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "origindive/3.1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Wayback Machine request failed: %w (archive.org may be temporarily unavailable)", err)
	}
	defer resp.Body.Close()

	// Check for service unavailability
	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout || resp.StatusCode == http.StatusBadGateway {
		return nil, fmt.Errorf("Wayback Machine API is temporarily unavailable (status %d). Please try again later", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("Wayback Machine returned status %d: %s", resp.StatusCode, strings.TrimSpace(bodyStr))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON array of arrays
	var records []CDXRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("failed to parse Wayback response: %w", err)
	}

	// Extract unique subdomains from URLs
	subdomainSet := make(map[string]bool)
	for i, record := range records {
		// Skip header row
		if i == 0 {
			continue
		}

		if len(record) == 0 {
			continue
		}

		// First field is the original URL
		urlStr := record[0]

		// Extract subdomain from URL
		subdomain := extractSubdomain(urlStr, domain)
		if subdomain != "" {
			subdomainSet[subdomain] = true
		}
	}

	// Convert to slice
	subdomains := make([]string, 0, len(subdomainSet))
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}

	// Resolve subdomains to IPs (limit to first 100 to avoid long delays)
	return resolveSubdomainsToIPs(ctx, subdomains, domain, 100, 3*time.Second)
}

// extractSubdomain extracts the subdomain from a URL
func extractSubdomain(urlStr, baseDomain string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")

	// Extract hostname (before first /)
	parts := strings.Split(urlStr, "/")
	if len(parts) == 0 {
		return ""
	}
	hostname := parts[0]

	// Remove port if present
	hostname = strings.Split(hostname, ":")[0]

	// Normalize both to lowercase for comparison
	hostnameLower := strings.ToLower(hostname)
	baseDomainLower := strings.ToLower(baseDomain)

	// Check if it ends with our base domain (case-insensitive)
	if !strings.HasSuffix(hostnameLower, baseDomainLower) {
		return ""
	}

	// Skip wildcards
	if strings.Contains(hostname, "*") {
		return ""
	}

	return hostnameLower
}

// resolveSubdomainsToIPs resolves a list of subdomains to IPv4 addresses
func resolveSubdomainsToIPs(ctx context.Context, subdomains []string, baseDomain string, maxResolve int, timeout time.Duration) ([]string, error) {
	ipSet := make(map[string]bool)
	resolver := &net.Resolver{}

	resolveCount := 0
	for _, subdomain := range subdomains {
		if resolveCount >= maxResolve {
			break
		}

		ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := resolver.LookupHost(ctxWithTimeout, subdomain)
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

		resolveCount++
	}

	// Convert to slice
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, nil
}
