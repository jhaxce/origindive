// Package censys provides Censys Search API integration for passive reconnaissance
package censys

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// CensysV3Request represents the request body for Censys v3 Global Search API
type CensysV3Request struct {
	Query     string   `json:"query"`                // CenQL query string (required)
	PageSize  int      `json:"page_size,omitempty"`  // Number of results per page (0-100)
	PageToken string   `json:"page_token,omitempty"` // Token for next page
	Fields    []string `json:"fields,omitempty"`     // Specific fields to return
}

// CensysResponse represents the JSON response from Censys Search API v3
type CensysResponse struct {
	Code   int          `json:"code"`
	Status string       `json:"status"`
	Result CensysResult `json:"result"`
	Error  string       `json:"error,omitempty"`
}

// CensysResult contains the search results
type CensysResult struct {
	Query string      `json:"query"`
	Total int         `json:"total"`
	Hits  []CensysHit `json:"hits"`
	Links CensysLinks `json:"links"`
}

// CensysHit represents a single host result
type CensysHit struct {
	IP       string                 `json:"ip"`
	Services []CensysService        `json:"services"`
	Location CensysLocation         `json:"location"`
	Names    []string               `json:"names"`
	Metadata map[string]interface{} `json:"metadata"`
}

// CensysService represents a service on the host
type CensysService struct {
	Port            int                    `json:"port"`
	ServiceName     string                 `json:"service_name"`
	TransportProto  string                 `json:"transport_protocol"`
	ExtendedService map[string]interface{} `json:"extended_service_name"`
	HTTP            CensysHTTP             `json:"http,omitempty"`
}

// CensysHTTP contains HTTP-specific service data
type CensysHTTP struct {
	Request  CensysHTTPRequest  `json:"request"`
	Response CensysHTTPResponse `json:"response"`
}

// CensysHTTPRequest contains HTTP request data
type CensysHTTPRequest struct {
	Host string `json:"host"`
	URI  string `json:"uri"`
}

// CensysHTTPResponse contains HTTP response data
type CensysHTTPResponse struct {
	StatusCode int    `json:"status_code"`
	HTMLTitle  string `json:"html_title"`
}

// CensysLocation contains geolocation data
type CensysLocation struct {
	Country     string     `json:"country"`
	City        string     `json:"city"`
	Coordinates [2]float64 `json:"coordinates"`
}

// CensysLinks contains pagination links
type CensysLinks struct {
	Next string `json:"next"`
	Prev string `json:"prev"`
}

// SearchHosts queries Censys for hosts matching the domain
func SearchHosts(ctx context.Context, domain string, tokens []string, orgID string, timeout time.Duration) ([]string, error) {
	if len(tokens) == 0 {
		return []string{}, fmt.Errorf("no Censys PAT tokens provided")
	}

	// Try each token until one works (rotation for rate limits)
	var lastErr error
	for i, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		ips, err := searchWithToken(ctx, domain, token, orgID, timeout)
		if err == nil {
			return ips, nil
		}

		// Check for rate limit errors
		if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "429") {
			lastErr = fmt.Errorf("token %d/%d rate limited: %w", i+1, len(tokens), err)
			continue // Try next token
		}

		// For other errors, return immediately (invalid token, network issue, etc.)
		return []string{}, fmt.Errorf("token %d/%d failed: %w", i+1, len(tokens), err)
	}

	if lastErr != nil {
		return []string{}, fmt.Errorf("all %d PAT tokens exhausted: %w", len(tokens), lastErr)
	}

	return []string{}, fmt.Errorf("no valid PAT tokens found")
}

// searchWithToken performs the search with a single PAT token
func searchWithToken(ctx context.Context, domain, token, orgID string, timeout time.Duration) ([]string, error) {
	// Build CenQL query for v3 Global Search API
	// Search for domain in certificate names: host.services.cert.names: "example.com"
	query := fmt.Sprintf(`host.services.cert.names: "%s"`, domain)

	// Create POST request body
	reqBody := CensysV3Request{
		Query:    query,
		PageSize: 100, // Max 100 results per page
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// v3 Global Search API endpoint (POST)
	url := "https://api.platform.censys.io/v3/global/search/query"
	// Add organization_id query parameter if provided (for paid plans)
	if orgID != "" {
		url += fmt.Sprintf("?organization_id=%s", orgID)
	}

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Censys PAT uses Bearer authentication
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "origindive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Censys request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		// Try to parse error from JSON with nested error structure (401 errors)
		var errorResponse struct {
			Error struct {
				Code    int    `json:"code"`
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &errorResponse) == nil && errorResponse.Error.Reason != "" {
			return nil, fmt.Errorf("Censys API error (HTTP %d): %s", resp.StatusCode, errorResponse.Error.Reason)
		}

		// Try to parse error with "detail" field (403 errors)
		var detailResponse struct {
			Title  string `json:"title"`
			Status int    `json:"status"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &detailResponse) == nil && detailResponse.Detail != "" {
			return nil, fmt.Errorf("Censys API error (HTTP %d): %s", resp.StatusCode, detailResponse.Detail)
		}

		// Fallback: Try simple error field
		var errResp CensysResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("Censys API error (HTTP %d): %s", resp.StatusCode, errResp.Error)
		}

		// Last resort: Truncate body for error message
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("Censys returned status %d: %s", resp.StatusCode, strings.TrimSpace(bodyStr))
	}

	// Parse successful response
	var censysResp CensysResponse
	if err := json.Unmarshal(body, &censysResp); err != nil {
		return nil, fmt.Errorf("failed to parse Censys response: %w", err)
	}

	// Check for API error in JSON (even with 200 OK)
	if censysResp.Error != "" {
		return nil, fmt.Errorf("Censys API error: %s", censysResp.Error)
	}

	// Extract unique IPv4 addresses
	ipSet := make(map[string]bool)
	for _, hit := range censysResp.Result.Hits {
		ip := strings.TrimSpace(hit.IP)
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
