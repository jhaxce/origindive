// Package waf provides WAF range auto-update functionality
package waf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// UpdateSource represents a source for updating WAF ranges
type UpdateSource struct {
	Provider    string `json:"provider"`
	URL         string `json:"url"`
	IPv4URL     string `json:"ipv4_url,omitempty"`
	IPv6URL     string `json:"ipv6_url,omitempty"`
	Format      string `json:"format"` // "text" or "json"
	JSONPath    string `json:"json_path,omitempty"`
	Description string `json:"description"`
}

// UpdateConfig represents the WAF update configuration
type UpdateConfig struct {
	UpdateIntervalHours int            `json:"update_interval_hours"`
	Sources             []UpdateSource `json:"sources"`
}

// LoadUpdateConfig loads the update configuration
func LoadUpdateConfig(filepath string) (*UpdateConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read update config: %w", err)
	}

	var config UpdateConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse update config: %w", err)
	}

	return &config, nil
}

// Updater handles WAF range updates
type Updater struct {
	config     *UpdateConfig
	dbPath     string
	httpClient *http.Client
}

// NewUpdater creates a new WAF range updater
func NewUpdater(configPath, dbPath string) (*Updater, error) {
	config, err := LoadUpdateConfig(configPath)
	if err != nil {
		return nil, err
	}

	return &Updater{
		config: config,
		dbPath: dbPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Update updates WAF ranges from configured sources
func (u *Updater) Update() error {
	// Load existing database
	db, err := LoadWAFDatabase(u.dbPath)
	if err != nil {
		// If database doesn't exist, create a new one
		db = &WAFDatabase{
			Sources:   make(map[string]string),
			Providers: make([]Provider, 0),
		}
	}

	// Update each provider
	for _, source := range u.config.Sources {
		fmt.Printf("Updating %s...\n", source.Provider)

		ranges, err := u.fetchRanges(&source)
		if err != nil {
			fmt.Printf("Warning: Failed to update %s: %v\n", source.Provider, err)
			continue
		}

		// Find or create provider in database
		provider := db.GetProvider(source.Provider)
		if provider == nil {
			// Create new provider
			db.Providers = append(db.Providers, Provider{
				ID:     source.Provider,
				Name:   strings.Title(strings.ReplaceAll(source.Provider, "-", " ")),
				Ranges: ranges,
			})
		} else {
			// Update existing provider
			provider.Ranges = ranges
		}

		// Update source URL
		url := source.URL
		if url == "" && source.IPv4URL != "" {
			url = source.IPv4URL
		}
		db.Sources[source.Provider] = url

		fmt.Printf("  Updated %s with %d ranges\n", source.Provider, len(ranges))
	}

	// Update last updated timestamp
	db.LastUpdated = time.Now()

	// Save updated database
	if err := SaveWAFDatabase(u.dbPath, db); err != nil {
		return fmt.Errorf("failed to save updated database: %w", err)
	}

	fmt.Printf("\nSuccessfully updated WAF database\n")
	fmt.Printf("Total providers: %d\n", len(db.Providers))
	fmt.Printf("Total ranges: %d\n", db.GetTotalRanges())

	return nil
}

// fetchRanges fetches IP ranges from a source
func (u *Updater) fetchRanges(source *UpdateSource) ([]string, error) {
	var ranges []string

	// Handle multiple URLs (e.g., separate IPv4 and IPv6)
	urls := make([]string, 0)
	if source.IPv4URL != "" {
		urls = append(urls, source.IPv4URL)
	}
	if source.IPv6URL != "" {
		urls = append(urls, source.IPv6URL)
	}
	if source.URL != "" && len(urls) == 0 {
		urls = append(urls, source.URL)
	}

	for _, url := range urls {
		fetchedRanges, err := u.fetchFromURL(url, source.Format, source.JSONPath)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, fetchedRanges...)
	}

	return ranges, nil
}

// fetchFromURL fetches and parses ranges from a URL
func (u *Updater) fetchFromURL(url, format, jsonPath string) ([]string, error) {
	resp, err := u.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from %s: %w (will use cached ranges if available)", url, err)
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("API rate limit exceeded for %s (using cached ranges)", url)
	}

	// Handle service errors
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("server error %d from %s (using cached ranges)", resp.StatusCode, url)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s (using cached ranges)", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	switch format {
	case "text":
		return u.parseTextRanges(body), nil
	case "json":
		return u.parseJSONRanges(body, jsonPath)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// parseTextRanges parses plain text CIDR list (one per line)
func (u *Updater) parseTextRanges(data []byte) []string {
	ranges := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ranges = append(ranges, line)
		}
	}

	return ranges
}

// parseJSONRanges parses JSON response and extracts IP ranges
// This is a simplified version - for production, use a proper JSON path library
func (u *Updater) parseJSONRanges(data []byte, jsonPath string) ([]string, error) {
	// Special handling for AWS IP ranges
	if strings.Contains(string(data), `"service"`) {
		return u.parseAWSRanges(data)
	}

	// Special handling for Fastly
	if strings.Contains(string(data), `"addresses"`) {
		return u.parseFastlyRanges(data)
	}

	return nil, fmt.Errorf("unsupported JSON format")
}

// parseAWSRanges parses AWS IP ranges JSON
func (u *Updater) parseAWSRanges(data []byte) ([]string, error) {
	var awsData struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(data, &awsData); err != nil {
		return nil, err
	}

	ranges := make([]string, 0)
	for _, prefix := range awsData.Prefixes {
		if prefix.Service == "CLOUDFRONT" {
			ranges = append(ranges, prefix.IPPrefix)
		}
	}

	return ranges, nil
}

// parseFastlyRanges parses Fastly IP list JSON
func (u *Updater) parseFastlyRanges(data []byte) ([]string, error) {
	var fastlyData struct {
		Addresses []string `json:"addresses"`
	}

	if err := json.Unmarshal(data, &fastlyData); err != nil {
		return nil, err
	}

	return fastlyData.Addresses, nil
}

// NeedsUpdate checks if the database needs updating based on last update time
func (u *Updater) NeedsUpdate() (bool, error) {
	db, err := LoadWAFDatabase(u.dbPath)
	if err != nil {
		return true, nil // Database doesn't exist or is invalid
	}

	if db.LastUpdated.IsZero() {
		return true, nil
	}

	elapsed := time.Since(db.LastUpdated)
	threshold := time.Duration(u.config.UpdateIntervalHours) * time.Hour

	return elapsed >= threshold, nil
}
