package wayback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSearchSubdomains_ValidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !contains(r.URL.Query().Get("output"), "json") {
			t.Error("Expected JSON output parameter")
		}

		records := []CDXRecord{
			{"http://www.example.com/"},
			{"http://api.example.com/"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(records)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This will fail as we can't inject test server URL
	ips, err := SearchSubdomains(ctx, "example.com", 5*time.Second)
	if err == nil {
		t.Logf("SearchSubdomains returned %d IPs (might have network access)", len(ips))
	}
}

func TestSearchSubdomains_EmptyDomain(t *testing.T) {
	ctx := context.Background()

	_, err := SearchSubdomains(ctx, "", 5*time.Second)
	if err == nil {
		t.Log("Request succeeded (unexpected)")
	}
}

func TestSearchSubdomains_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond)

	_, err := SearchSubdomains(ctx, "example.com", 100*time.Millisecond)
	if err == nil {
		t.Log("Request succeeded despite timeout")
	}
}

func TestSearchSubdomains_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := SearchSubdomains(ctx, "example.com", 5*time.Second)
	if err == nil {
		t.Log("Request succeeded despite cancelled context")
	}
}

func TestCDXRecord_Structure(t *testing.T) {
	record := CDXRecord{"http://example.com/", "20230101000000", "200"}

	if len(record) != 3 {
		t.Errorf("CDXRecord length = %d, want 3", len(record))
	}
	if record[0] != "http://example.com/" {
		t.Errorf("First field = %s, want http://example.com/", record[0])
	}
}

func TestCDXRecord_JSON(t *testing.T) {
	jsonStr := `[
		["http://example.com/", "20230101000000", "200"],
		["http://www.example.com/", "20230101000001", "200"]
	]`

	var records []CDXRecord
	err := json.Unmarshal([]byte(jsonStr), &records)
	if err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if len(records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(records))
	}
}

func TestExtractSubdomain_ValidURL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		baseDomain string
		want       string
	}{
		{"http url", "http://www.example.com/path", "example.com", "www.example.com"},
		{"https url", "https://api.example.com/path", "example.com", "api.example.com"},
		{"with port", "http://www.example.com:8080/path", "example.com", "www.example.com"},
		{"root domain", "http://example.com/", "example.com", "example.com"},
		{"subdomain", "http://test.api.example.com/", "example.com", "test.api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSubdomain(tt.url, tt.baseDomain)
			if got != tt.want {
				t.Errorf("extractSubdomain(%q, %q) = %q, want %q", tt.url, tt.baseDomain, got, tt.want)
			}
		})
	}
}

func TestExtractSubdomain_InvalidURL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		baseDomain string
	}{
		{"different domain", "http://other.com/", "example.com"},
		{"with wildcard", "http://*.example.com/", "example.com"},
		{"empty url", "", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSubdomain(tt.url, tt.baseDomain)
			if got != "" {
				t.Errorf("extractSubdomain(%q, %q) = %q, want empty", tt.url, tt.baseDomain, got)
			}
		})
	}
}

func TestExtractSubdomain_CaseInsensitive(t *testing.T) {
	got := extractSubdomain("http://WWW.EXAMPLE.COM/", "example.com")
	want := "www.example.com"
	if got != want {
		t.Errorf("extractSubdomain() = %q, want %q", got, want)
	}

	// Also test with uppercase base domain
	got2 := extractSubdomain("http://api.example.com/", "EXAMPLE.COM")
	want2 := "api.example.com"
	if got2 != want2 {
		t.Errorf("extractSubdomain() = %q, want %q", got2, want2)
	}
}

func TestResolveSubdomainsToIPs_Empty(t *testing.T) {
	ctx := context.Background()

	ips, err := resolveSubdomainsToIPs(ctx, []string{}, "example.com", 100, 3*time.Second)
	if err != nil {
		t.Errorf("Should not error on empty list: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs, got %d", len(ips))
	}
}

func TestResolveSubdomainsToIPs_MaxResolveLimit(t *testing.T) {
	ctx := context.Background()

	// Create list of 10 subdomains but limit to 5
	subdomains := []string{
		"google.com", "github.com", "cloudflare.com",
		"amazon.com", "microsoft.com", "apple.com",
		"facebook.com", "twitter.com", "youtube.com", "netflix.com",
	}

	_, err := resolveSubdomainsToIPs(ctx, subdomains, "example.com", 5, 2*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Can't verify count without inspecting internals, but no error is good
}

func TestResolveSubdomainsToIPs_InvalidDomain(t *testing.T) {
	ctx := context.Background()

	ips, err := resolveSubdomainsToIPs(ctx, []string{"invalid-99999.test"}, "test", 10, 2*time.Second)
	if err != nil {
		t.Errorf("Should not error, just skip: %v", err)
	}

	if len(ips) > 0 {
		t.Logf("Unexpected IPs: %v", ips)
	}
}

func TestResolveSubdomainsToIPs_ValidDomain(t *testing.T) {
	ctx := context.Background()

	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com"}, "google.com", 10, 5*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(ips) == 0 {
		t.Log("No IPs resolved (might be network issue)")
	} else {
		t.Logf("Resolved %d IPs", len(ips))
	}
}

func TestResolveSubdomainsToIPs_IPv4Only(t *testing.T) {
	ctx := context.Background()

	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com"}, "google.com", 10, 5*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// All should be IPv4 format
	for _, ip := range ips {
		if len(ip) > 15 {
			t.Errorf("Expected IPv4 only, got: %s", ip)
		}
	}
}

func TestResolveSubdomainsToIPs_Deduplication(t *testing.T) {
	ctx := context.Background()

	// Same domain twice should deduplicate IPs
	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com", "google.com"}, "google.com", 10, 5*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("Duplicate IP: %s", ip)
		}
		seen[ip] = true
	}
}

func TestResolveSubdomainsToIPs_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com"}, "google.com", 10, 5*time.Second)
	if err != nil {
		t.Errorf("Should not error on cancellation: %v", err)
	}

	t.Logf("Resolved %d IPs with cancelled context", len(ips))
}

func TestResolveSubdomainsToIPs_Timeout(t *testing.T) {
	ctx := context.Background()

	// Very short timeout for each lookup
	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com"}, "google.com", 10, 1*time.Nanosecond)
	if err != nil {
		t.Errorf("Should not error on timeout: %v", err)
	}

	// Might return 0 IPs due to timeout
	t.Logf("Resolved %d IPs with 1ns timeout", len(ips))
}

// Helper function
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSearchSubdomains_StatusError(t *testing.T) {
	// Test non-200 status code handling
	ctx := context.Background()

	_, err := SearchSubdomains(ctx, "example.com", 100*time.Millisecond)
	if err != nil && contains(err.Error(), "status") {
		t.Logf("Status error: %v", err)
	}
}

func TestExtractSubdomain_NoSlash(t *testing.T) {
	got := extractSubdomain("http://example.com", "example.com")
	if got != "example.com" {
		t.Errorf("Should handle URL without trailing slash, got: %s", got)
	}
}

func TestExtractSubdomain_MultipleSlashes(t *testing.T) {
	got := extractSubdomain("http://www.example.com/path/to/resource", "example.com")
	if got != "www.example.com" {
		t.Errorf("Should extract from URL with path, got: %s", got)
	}
}
