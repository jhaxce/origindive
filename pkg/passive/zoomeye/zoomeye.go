// Package zoomeye provides ZoomEye API integration for passive reconnaissance
package zoomeye

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ZoomEyeV2Request represents the request body for ZoomEye v2 POST API
type ZoomEyeV2Request struct {
	QBase64  string `json:"qbase64"`
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"pagesize,omitempty"`
	SubType  string `json:"sub_type,omitempty"`
}

// ZoomEyeV2Response represents the JSON response from ZoomEye API v2
type ZoomEyeV2Response struct {
	Code    int              `json:"code"`
	Message string           `json:"message"`
	Total   int              `json:"total"`
	Query   string           `json:"query"`
	Data    []ZoomEyeV2Asset `json:"data"`
}

// ZoomEyeV2Asset represents a single asset from v2 API
type ZoomEyeV2Asset struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Domain     string `json:"domain"`
	Hostname   string `json:"hostname"`
	URL        string `json:"url"`
	UpdateTime string `json:"update_time"`
}

// apiURL is the ZoomEye v2 API endpoint (can be overridden in tests)
var apiURL = "https://api.zoomeye.ai/v2/search"

// SearchHost queries ZoomEye for hosts matching the domain
func SearchHost(ctx context.Context, domain string, apiKeys []string, timeout time.Duration) ([]string, error) {
	if len(apiKeys) == 0 {
		return []string{}, fmt.Errorf("no ZoomEye API keys provided")
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
	// Build query: ssl.cert.subject.cn="domain.com" and encode with base64
	query := fmt.Sprintf(`ssl.cert.subject.cn="%s"`, domain)
	encodedQuery := base64.StdEncoding.EncodeToString([]byte(query))

	// Create POST request body for v2 API
	reqBody := ZoomEyeV2Request{
		QBase64:  encodedQuery,
		Page:     1,
		PageSize: 100,
		SubType:  "v4", // IPv4 only
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Use v2 POST API endpoint (from package variable)
	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// ZoomEye uses API-KEY header
	req.Header.Set("API-KEY", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "origindive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ZoomEye request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		// Try to parse error from JSON
		var errResp ZoomEyeV2Response
		if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
			return nil, fmt.Errorf("ZoomEye API error (HTTP %d): %s", resp.StatusCode, errResp.Message)
		}

		// Truncate body for error message
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("ZoomEye returned status %d: %s", resp.StatusCode, strings.TrimSpace(bodyStr))
	}

	// Parse successful response using v2 structure
	var zoomeyeResp ZoomEyeV2Response
	if err := json.Unmarshal(body, &zoomeyeResp); err != nil {
		return nil, fmt.Errorf("failed to parse ZoomEye response: %w", err)
	}

	// Check for API error in JSON
	if zoomeyeResp.Code != 60000 {
		return nil, fmt.Errorf("ZoomEye API error (code %d): %s", zoomeyeResp.Code, zoomeyeResp.Message)
	}

	// Extract unique IPv4 addresses
	ipSet := make(map[string]bool)
	for _, asset := range zoomeyeResp.Data {
		ip := strings.TrimSpace(asset.IP)
		if ip == "" {
			continue
		}

		// Validate and filter IPv4 only
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		// Check if IPv4 (To4() returns nil for IPv6)
		if parsedIP.To4() != nil {
			ipSet[ip] = true
		}
	}

	// Convert to slice
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, nil
}
