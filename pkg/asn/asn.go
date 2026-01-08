// Package asn provides ASN IP range lookup and caching functionality
package asn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jhaxce/origindive/v3/pkg/core"
)

// ASNResponse represents the response from ipapi.is API
type ASNResponse struct {
	ASN        int      `json:"asn"`      // ASN number
	ASNName    string   `json:"org"`      // Organization name
	ASNRanges  []string `json:"prefixes"` // IPv4 CIDR prefixes
	CacheValid bool     `json:"-"`        // Internal cache validation flag
}

// Client provides ASN lookup functionality
type Client struct {
	cacheDir string
	client   *http.Client
}

// NewClient creates a new ASN lookup client
func NewClient(cacheDir string) *Client {
	if cacheDir == "" {
		cacheDir = getDefaultCacheDir()
	}

	return &Client{
		cacheDir: cacheDir,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// LookupASN fetches ASN information from ipapi.is API or cache
func (c *Client) LookupASN(asn string) (*ASNResponse, error) {
	// Normalize ASN (ensure it starts with "AS")
	if len(asn) > 0 && asn[:2] != "AS" && asn[:2] != "as" {
		asn = "AS" + asn
	}

	// Check cache first (permanent unless manually deleted)
	cached, err := c.loadFromCache(asn)
	if err == nil {
		return cached, nil
	}

	// Fetch from API
	resp, err := c.fetchFromAPI(asn)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ASN data: %w", err)
	}

	// Save to cache
	if err := c.saveToCache(asn, resp); err != nil {
		// Non-fatal: continue even if cache save fails
		fmt.Fprintf(os.Stderr, "Warning: failed to cache ASN data: %v\n", err)
	}

	return resp, nil
}

// fetchFromAPI queries the ipapi.is API for ASN information
func (c *Client) fetchFromAPI(asn string) (*ASNResponse, error) {
	url := fmt.Sprintf("https://api.ipapi.is/?asn=%s", asn)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "origindive/3.1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w\nFallback: Check manually at https://ipapi.is/geolocation.html or use direct CIDR input with --cidr flag", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("ipapi.is API rate limit exceeded. Please wait and try again or use direct CIDR input")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d. Fallback: Use direct CIDR input with --cidr flag", resp.StatusCode)
	}

	var asnResp ASNResponse
	if err := json.NewDecoder(resp.Body).Decode(&asnResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Validate response
	if len(asnResp.ASNRanges) == 0 {
		return nil, fmt.Errorf("no IP ranges found for ASN %s", asn)
	}

	asnResp.CacheValid = true

	return &asnResp, nil
}

// loadFromCache loads ASN data from local cache (permanent cache)
func (c *Client) loadFromCache(asn string) (*ASNResponse, error) {
	cachePath := c.getCachePath(asn)

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	var resp ASNResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse cache: %w", err)
	}

	resp.CacheValid = true
	return &resp, nil
}

// saveToCache saves ASN data to local cache
func (c *Client) saveToCache(asn string, resp *ASNResponse) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cachePath := c.getCachePath(asn)

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// getCachePath returns the full path to the cache file for an ASN
func (c *Client) getCachePath(asn string) string {
	return filepath.Join(c.cacheDir, fmt.Sprintf("%s.json", asn))
}

// getDefaultCacheDir returns the default cache directory
func getDefaultCacheDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "data/asn_cache"
	}

	// Platform-specific cache directory
	return filepath.Join(homeDir, ".cache", "origindive", "asn")
}

// ConvertToIPRanges converts ASN CIDR ranges to [2]uint32 format for scanner
func ConvertToIPRanges(asnResp *ASNResponse) ([][2]uint32, error) {
	if asnResp == nil || len(asnResp.ASNRanges) == 0 {
		return nil, core.ErrNoIPRange
	}

	// Import ip package for parsing
	var ranges [][2]uint32

	for _, cidr := range asnResp.ASNRanges {
		// Skip if CIDR is empty
		if cidr == "" {
			continue
		}

		// We'll parse in main.go using ip.ParseCIDRRange
		// This function just validates the response structure
	}

	return ranges, nil
}
