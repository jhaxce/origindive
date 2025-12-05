// Package api provides API client validation and failover for passive sources
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ShodanValidator validates Shodan API key
func ShodanValidator(apiKey string) func(context.Context) error {
	return func(ctx context.Context) error {
		if apiKey == "" {
			return fmt.Errorf("shodan API key not configured")
		}

		// Test API key with account info endpoint
		url := fmt.Sprintf("https://api.shodan.io/account/profile?key=%s", apiKey)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("shodan API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			return fmt.Errorf("shodan API key is invalid")
		}
		if resp.StatusCode == 429 {
			return fmt.Errorf("shodan rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("shodan API returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// CensysValidator validates Censys API credentials
func CensysValidator(apiID, apiSecret string) func(context.Context) error {
	return func(ctx context.Context) error {
		if apiID == "" || apiSecret == "" {
			return fmt.Errorf("censys API credentials not configured")
		}

		// Test credentials with account endpoint
		url := "https://search.censys.io/api/v2/account"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.SetBasicAuth(apiID, apiSecret)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("censys API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return fmt.Errorf("censys API credentials are invalid")
		}
		if resp.StatusCode == 429 {
			return fmt.Errorf("censys rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("censys API returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// CTValidator validates Certificate Transparency access (no API key needed)
func CTValidator() func(context.Context) error {
	return func(ctx context.Context) error {
		// Test crt.sh availability
		url := "https://crt.sh/?output=json&q=example.com"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("certificate transparency service unavailable: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			return fmt.Errorf("certificate transparency rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("certificate transparency returned status %d", resp.StatusCode)
		}

		// Check if response is valid JSON array
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		var result []map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("certificate transparency returned invalid JSON: %w", err)
		}

		// Validate expected fields exist (based on crt.sh format)
		if len(result) > 0 {
			firstEntry := result[0]
			requiredFields := []string{"issuer_ca_id", "issuer_name", "common_name", "name_value", "id"}
			for _, field := range requiredFields {
				if _, ok := firstEntry[field]; !ok {
					return fmt.Errorf("certificate transparency response missing field: %s", field)
				}
			}
		}

		return nil
	}
}

// SecurityTrailsValidator validates SecurityTrails API key
func SecurityTrailsValidator(apiKey string) func(context.Context) error {
	return func(ctx context.Context) error {
		if apiKey == "" || strings.Contains(apiKey, "YOUR_") {
			return fmt.Errorf("securitytrails API key not configured")
		}

		// Test with usage endpoint
		url := "https://api.securitytrails.com/v1/account/usage"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("APIKEY", apiKey)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("securitytrails API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return fmt.Errorf("securitytrails API key is invalid")
		}
		if resp.StatusCode == 429 {
			return fmt.Errorf("securitytrails rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("securitytrails API returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// VirusTotalValidator validates VirusTotal API key
func VirusTotalValidator(apiKey string) func(context.Context) error {
	return func(ctx context.Context) error {
		if apiKey == "" || strings.Contains(apiKey, "YOUR_") || len(apiKey) != 64 {
			return fmt.Errorf("virustotal API key not configured or invalid length")
		}

		// Test with domains endpoint
		url := "https://www.virustotal.com/api/v3/domains/google.com"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("x-apikey", apiKey)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("virustotal API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return fmt.Errorf("virustotal API key is invalid")
		}
		if resp.StatusCode == 429 {
			return fmt.Errorf("virustotal rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("virustotal API returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// ZoomEyeValidator validates ZoomEye API key
func ZoomEyeValidator(apiKey string) func(context.Context) error {
	return func(ctx context.Context) error {
		if apiKey == "" || strings.Contains(apiKey, "YOUR_") {
			return fmt.Errorf("zoomeye API key not configured")
		}

		// Test with resources endpoint
		url := "https://api.zoomeye.org/resources-info"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("API-KEY", apiKey)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("zoomeye API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return fmt.Errorf("zoomeye API key is invalid")
		}
		if resp.StatusCode == 429 {
			return fmt.Errorf("zoomeye rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("zoomeye API returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// ViewDNSValidator validates ViewDNS API access (free service)
func ViewDNSValidator() func(context.Context) error {
	return func(ctx context.Context) error {
		// ViewDNS is free but rate-limited, just check availability
		url := "https://viewdns.info/reverseip/?host=8.8.8.8&t=1"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("viewdns service unavailable: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return fmt.Errorf("viewdns returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// DNSDumpsterValidator validates DNSDumpster API access (free service)
func DNSDumpsterValidator() func(context.Context) error {
	return func(ctx context.Context) error {
		// DNSDumpster is free, no validation needed
		// Service availability is checked during actual use
		return nil
	}
}

// WaybackValidator validates Wayback Machine access (free service)
func WaybackValidator() func(context.Context) error {
	return func(ctx context.Context) error {
		// Test Wayback availability
		url := "https://web.archive.org/cdx/search/cdx?url=example.com&output=json&limit=1"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("wayback machine service unavailable: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			return fmt.Errorf("wayback machine rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("wayback machine returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// DNSValidator validates DNS resolution capability (no API key needed)
func DNSValidator() func(context.Context) error {
	return func(ctx context.Context) error {
		// DNS is always available unless there's a network issue
		return nil
	}
}

// GetValidator returns the appropriate validator for a source
func GetValidator(source Source, shodanKey, censysID, censysSecret, stKey, vtKey, zeKey string) func(context.Context) error {
	switch source {
	case SourceShodan:
		return ShodanValidator(shodanKey)
	case SourceCensys:
		return CensysValidator(censysID, censysSecret)
	case SourceSecurityTrails:
		return SecurityTrailsValidator(stKey)
	case SourceVirusTotal:
		return VirusTotalValidator(vtKey)
	case SourceZoomEye:
		return ZoomEyeValidator(zeKey)
	case SourceCT:
		return CTValidator()
	case SourceViewDNS:
		return ViewDNSValidator()
	case SourceDNSDumpster:
		return DNSDumpsterValidator()
	case SourceWayback:
		return WaybackValidator()
	case SourceDNS:
		return DNSValidator()
	default:
		return func(ctx context.Context) error {
			return fmt.Errorf("unknown source: %s", source)
		}
	}
}

// ValidateAllSources checks all configured sources and returns available ones
func ValidateAllSources(ctx context.Context, shodanKeys, censysTokens, stKeys, vtKeys, zeKeys []string, censysOrgID string) map[string]bool {
	available := make(map[string]bool)

	// Sources that always work (no API key needed)
	available["ct"] = true
	available["dns"] = true
	available["viewdns"] = true
	available["dnsdumpster"] = true
	available["wayback"] = true

	// Validate Shodan
	if len(shodanKeys) > 0 && shodanKeys[0] != "" {
		if err := ShodanValidator(shodanKeys[0])(ctx); err == nil {
			available["shodan"] = true
		}
	}

	// Validate Censys
	if len(censysTokens) > 0 && censysTokens[0] != "" && censysOrgID != "" {
		if err := CensysValidator(censysTokens[0], censysOrgID)(ctx); err == nil {
			available["censys"] = true
		}
	}

	// Validate SecurityTrails
	if len(stKeys) > 0 && stKeys[0] != "" {
		if err := SecurityTrailsValidator(stKeys[0])(ctx); err == nil {
			available["securitytrails"] = true
		}
	}

	// Validate VirusTotal
	if len(vtKeys) > 0 && vtKeys[0] != "" {
		if err := VirusTotalValidator(vtKeys[0])(ctx); err == nil {
			available["virustotal"] = true
		}
	}

	// Validate ZoomEye
	if len(zeKeys) > 0 && zeKeys[0] != "" {
		if err := ZoomEyeValidator(zeKeys[0])(ctx); err == nil {
			available["zoomeye"] = true
		}
	}

	return available
}

// GetAvailableSources returns list of available source IDs
func GetAvailableSources(ctx context.Context, shodanKeys, censysTokens, stKeys, vtKeys, zeKeys []string, censysOrgID string) []string {
	availableMap := ValidateAllSources(ctx, shodanKeys, censysTokens, stKeys, vtKeys, zeKeys, censysOrgID)

	var sources []string
	for source := range availableMap {
		sources = append(sources, source)
	}

	return sources
}

// FilterRequestedSources filters requested sources by availability
// If requestedSources is empty, returns all available sources (auto mode)
func FilterRequestedSources(ctx context.Context, requestedSources []string, shodanKeys, censysTokens, stKeys, vtKeys, zeKeys []string, censysOrgID string) []string {
	availableMap := ValidateAllSources(ctx, shodanKeys, censysTokens, stKeys, vtKeys, zeKeys, censysOrgID)

	// Auto mode: use all available
	if len(requestedSources) == 0 {
		return GetAvailableSources(ctx, shodanKeys, censysTokens, stKeys, vtKeys, zeKeys, censysOrgID)
	}

	// Filter requested by available
	var filtered []string
	for _, src := range requestedSources {
		if availableMap[src] {
			filtered = append(filtered, src)
		}
	}

	return filtered
}
