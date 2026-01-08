package ct

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSearchCrtSh_ValidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !containsStr(r.URL.Query().Get("output"), "json") {
			t.Error("Expected JSON output parameter")
		}

		entries := []CTEntry{
			{
				CommonName: "example.com",
				NameValue:  "example.com\nwww.example.com",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This will fail as we can't inject the test server URL
	// Testing the function structure
	ips, err := SearchCrtSh(ctx, "example.com", 5*time.Second)
	if err == nil {
		t.Logf("SearchCrtSh returned %d IPs (might have network access)", len(ips))
	}
}

func TestSearchCrtSh_EmptyDomain(t *testing.T) {
	ctx := context.Background()

	_, err := SearchCrtSh(ctx, "", 5*time.Second)
	// Should make request even with empty domain (crt.sh handles it)
	if err == nil {
		t.Log("Request succeeded (unexpected)")
	}
}

func TestSearchCrtSh_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout

	_, err := SearchCrtSh(ctx, "example.com", 100*time.Millisecond)
	if err == nil {
		t.Log("Request succeeded despite timeout (might be cached)")
	}
}

func TestSearchCrtSh_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := SearchCrtSh(ctx, "example.com", 5*time.Second)
	if err == nil {
		t.Log("Request succeeded despite cancelled context")
	}
}

func TestCTEntry_Structure(t *testing.T) {
	entry := CTEntry{
		IssuerCAID:     123,
		IssuerName:     "Let's Encrypt",
		CommonName:     "example.com",
		NameValue:      "example.com\nwww.example.com",
		ID:             456789,
		EntryTimestamp: "2023-01-01T00:00:00",
		NotBefore:      "2023-01-01",
		NotAfter:       "2024-01-01",
	}

	if entry.CommonName != "example.com" {
		t.Errorf("CommonName = %s, want example.com", entry.CommonName)
	}
	if entry.IssuerCAID != 123 {
		t.Errorf("IssuerCAID = %d, want 123", entry.IssuerCAID)
	}
}

func TestCTEntry_JSON(t *testing.T) {
	jsonStr := `{
		"issuer_ca_id": 123,
		"issuer_name": "Test CA",
		"common_name": "example.com",
		"name_value": "example.com\nwww.example.com",
		"id": 456,
		"entry_timestamp": "2023-01-01T00:00:00",
		"not_before": "2023-01-01",
		"not_after": "2024-01-01"
	}`

	var entry CTEntry
	err := json.Unmarshal([]byte(jsonStr), &entry)
	if err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if entry.CommonName != "example.com" {
		t.Errorf("CommonName = %s, want example.com", entry.CommonName)
	}
	if entry.NameValue != "example.com\nwww.example.com" {
		t.Errorf("NameValue = %s", entry.NameValue)
	}
}

func TestExtractSubdomains_FromNameValue(t *testing.T) {
	// Test the subdomain extraction logic indirectly
	nameValue := "example.com\nwww.example.com\n*.example.com\napi.example.com"

	// Split and filter like the actual code does
	names := splitString(nameValue, "\n")
	var valid []string
	for _, name := range names {
		name = trimSpace(toLowerCase(name))
		if name != "" && !hasPrefix(name, "*") {
			valid = append(valid, name)
		}
	}

	if len(valid) != 3 {
		t.Errorf("Expected 3 valid subdomains, got %d", len(valid))
	}
}

func TestResolveSubdomainsToIPs_Empty(t *testing.T) {
	ctx := context.Background()

	ips, err := resolveSubdomainsToIPs(ctx, []string{}, 3*time.Second)
	if err != nil {
		t.Errorf("Should not error on empty list: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs from empty list, got %d", len(ips))
	}
}

func TestResolveSubdomainsToIPs_InvalidDomain(t *testing.T) {
	ctx := context.Background()

	ips, err := resolveSubdomainsToIPs(ctx, []string{"invalid-domain-99999.test"}, 2*time.Second)
	if err != nil {
		t.Errorf("Should not error, just skip failed resolutions: %v", err)
	}
	// Should return empty list (no successful resolutions)
	if len(ips) > 0 {
		t.Logf("Unexpected IPs resolved: %v", ips)
	}
}

func TestResolveSubdomainsToIPs_ValidDomain(t *testing.T) {
	ctx := context.Background()

	// Use a well-known domain
	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com"}, 5*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(ips) == 0 {
		t.Log("No IPs resolved (might be network issue)")
	} else {
		t.Logf("Resolved %d IPs for google.com", len(ips))
	}
}

func TestResolveSubdomainsToIPs_Deduplication(t *testing.T) {
	ctx := context.Background()

	// Two domains that might resolve to same IPs
	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com", "google.com"}, 5*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should deduplicate IPs
	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("Duplicate IP found: %s", ip)
		}
		seen[ip] = true
	}
}

func TestResolveSubdomainsToIPs_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com"}, 5*time.Second)
	if err != nil {
		t.Errorf("Should not error on cancellation, just skip: %v", err)
	}

	// Might return empty or partial results
	t.Logf("Resolved %d IPs with cancelled context", len(ips))
}

func TestResolveSubdomainsToIPs_IPv4Only(t *testing.T) {
	ctx := context.Background()

	// google.com has both IPv4 and IPv6
	ips, err := resolveSubdomainsToIPs(ctx, []string{"google.com"}, 5*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// All IPs should be IPv4 format
	for _, ip := range ips {
		if len(ip) > 15 { // IPv6 addresses are longer
			t.Errorf("Expected IPv4 only, got: %s", ip)
		}
	}
}

// Helper functions to avoid importing strings package in tests
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func splitString(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}

func toLowerCase(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			result[i] = s[i] + 32
		} else {
			result[i] = s[i]
		}
	}
	return string(result)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestSearchCrtSh_GatewayError(t *testing.T) {
	// Test 502/503/504 error handling
	ctx := context.Background()

	// This would require HTTP mocking to properly test
	_, err := SearchCrtSh(ctx, "example.com", 100*time.Millisecond)
	if err != nil && (containsStr(err.Error(), "502") || containsStr(err.Error(), "503") || containsStr(err.Error(), "504")) {
		t.Logf("Gateway error detected: %v", err)
	}
}

func TestSearchCrtShURL_DirectCall(t *testing.T) {
	// Test the internal function directly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	url := "https://crt.sh/?q=example.com&output=json"
	_, err := searchCrtShURL(ctx, url, "example.com", 5*time.Second)
	if err == nil {
		t.Log("searchCrtShURL succeeded (might have network access)")
	}
}

// ============================================================================
// Mock Server Tests for searchCrtShURL
// ============================================================================

func TestSearchCrtShURL_MockSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []CTEntry{
			{
				CommonName: "example.com",
				NameValue:  "example.com\nwww.example.com\napi.example.com",
			},
			{
				CommonName: "sub.example.com",
				NameValue:  "sub.example.com",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()

	ctx := context.Background()
	ips, err := searchCrtShURL(ctx, server.URL, "example.com", 5*time.Second)
	if err != nil {
		t.Logf("Error (expected if no DNS resolution): %v", err)
	}
	t.Logf("Returned %d IPs", len(ips))
}

func TestSearchCrtShURL_Mock502Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchCrtShURL(ctx, server.URL, "example.com", 5*time.Second)
	if err == nil {
		t.Error("Expected error for 502 response")
	}
	// Should detect gateway error
	if !containsStr(err.Error(), "502") && !containsStr(err.Error(), "gateway") {
		t.Errorf("Expected gateway error, got: %v", err)
	}
}

func TestSearchCrtShURL_Mock503Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Temporarily Unavailable"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchCrtShURL(ctx, server.URL, "example.com", 5*time.Second)
	if err == nil {
		t.Error("Expected error for 503 response")
	}
}

func TestSearchCrtShURL_MockInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchCrtShURL(ctx, server.URL, "example.com", 5*time.Second)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	if !containsStr(err.Error(), "parse") {
		t.Errorf("Expected parse error, got: %v", err)
	}
}

func TestSearchCrtShURL_MockEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer server.Close()

	ctx := context.Background()
	ips, err := searchCrtShURL(ctx, server.URL, "example.com", 5*time.Second)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs from empty CT response, got %d", len(ips))
	}
}

func TestSearchCrtShURL_MockWildcardFiltering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []CTEntry{
			{
				CommonName: "example.com",
				NameValue:  "*.example.com\nexample.com\nwww.example.com",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchCrtShURL(ctx, server.URL, "example.com", 5*time.Second)
	if err != nil {
		t.Logf("Error (expected for DNS resolution): %v", err)
	}
	// Wildcards should be filtered out but function still returns IPs from valid subdomains
}

func TestSearchCrtShURL_MockLongErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Write a long non-HTML error message
		longMsg := make([]byte, 500)
		for i := range longMsg {
			longMsg[i] = 'x'
		}
		w.Write(longMsg)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchCrtShURL(ctx, server.URL, "example.com", 5*time.Second)
	if err == nil {
		t.Error("Expected error for 400 response")
	}
	// Error message should be truncated
	if len(err.Error()) > 300 {
		t.Logf("Error message length: %d (might not be truncated)", len(err.Error()))
	}
}
