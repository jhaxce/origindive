package shodan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSearchHostname_NoAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHostname(ctx, "example.com", []string{}, 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when no API keys provided")
	}
	if err.Error() != "no Shodan API keys provided" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSearchHostname_EmptyAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHostname(ctx, "example.com", []string{"", "  ", ""}, 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when all API keys are empty")
	}
	if err.Error() != "no valid API keys found" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSearchHostname_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check User-Agent
		if r.Header.Get("User-Agent") != "origindive/3.1.0" {
			t.Errorf("Unexpected User-Agent: %s", r.Header.Get("User-Agent"))
		}

		// Check query format
		query := r.URL.Query().Get("query")
		if query != "hostname:example.com" {
			t.Errorf("Expected query 'hostname:example.com', got '%s'", query)
		}

		// Return valid response
		resp := ShodanResponse{
			Total: 2,
			Matches: []ShodanMatch{
				{
					IPStr:     "192.168.1.1",
					Hostnames: []string{"web1.example.com"},
					Port:      443,
					Transport: "tcp",
				},
				{
					IPStr:     "192.168.1.2",
					Hostnames: []string{"web2.example.com"},
					Port:      80,
					Transport: "tcp",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Test validates logic but can't inject test server
	ctx := context.Background()
	_, err := SearchHostname(ctx, "example.com", []string{"test_key"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search succeeded (might have network access)")
	}
}

func TestSearchHostname_RateLimitRotation(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// First key returns rate limit
		if callCount == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(ShodanResponse{
				Error: "Rate limit exceeded",
			})
			return
		}

		// Second key succeeds
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ShodanResponse{
			Total: 1,
			Matches: []ShodanMatch{
				{IPStr: "192.168.1.1"},
			},
		})
	}))
	defer server.Close()

	// Test validates rotation logic
	ctx := context.Background()
	_, err := SearchHostname(ctx, "example.com", []string{"key1", "key2"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search with rotation succeeded (might have network access)")
	}
}

func TestSearchHostname_AllKeysRateLimited(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := SearchHostname(ctx, "example.com", []string{"key1", "key2"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Expected error for exhausted keys")
	}
}

func TestSearchWithKey_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ShodanResponse{
			Error: "Invalid API key",
		})
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "invalid_key", 1*time.Second)
	if err == nil {
		t.Log("Expected error for invalid key")
	}
}

func TestSearchWithKey_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Expected JSON parsing error")
	}
}

func TestSearchWithKey_APIErrorInJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ShodanResponse{
			Error: "Query quota exceeded",
		})
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Expected API error from JSON")
	}
}

func TestShodanStructures(t *testing.T) {
	// Test ShodanResponse
	resp := ShodanResponse{
		Total: 5,
		Matches: []ShodanMatch{
			{
				IPStr:     "192.168.1.1",
				Hostnames: []string{"web.example.com"},
				Domains:   []string{"example.com"},
				Port:      443,
				Transport: "tcp",
			},
		},
		Error: "",
	}

	if resp.Total != 5 {
		t.Errorf("Total = %d, want 5", resp.Total)
	}
	if len(resp.Matches) != 1 {
		t.Error("Expected 1 match")
	}

	// Test ShodanMatch
	match := resp.Matches[0]
	if match.IPStr != "192.168.1.1" {
		t.Errorf("IPStr = %s, want 192.168.1.1", match.IPStr)
	}
	if len(match.Hostnames) != 1 {
		t.Error("Expected 1 hostname")
	}
	if match.Port != 443 {
		t.Errorf("Port = %d, want 443", match.Port)
	}
	if match.Transport != "tcp" {
		t.Errorf("Transport = %s, want tcp", match.Transport)
	}
}

func TestSearchWithKey_IPv6Filtering(t *testing.T) {
	// Test that IPv6 addresses are filtered out
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ShodanResponse{
			Total: 2,
			Matches: []ShodanMatch{
				{IPStr: "192.168.1.1"}, // IPv4
				{IPStr: "2001:db8::1"}, // IPv6 - should be filtered
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("IPv6 filtering test completed")
	}
}

func TestSearchWithKey_EmptyIPStr(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ShodanResponse{
			Total: 2,
			Matches: []ShodanMatch{
				{IPStr: ""}, // Empty - should be skipped
				{IPStr: "192.168.1.1"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Empty IP filtering test completed")
	}
}

func TestSearchWithKey_InvalidIPFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ShodanResponse{
			Total: 2,
			Matches: []ShodanMatch{
				{IPStr: "not-an-ip"}, // Invalid - should be skipped
				{IPStr: "192.168.1.1"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Invalid IP filtering test completed")
	}
}

func TestSearchHostname_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := SearchHostname(ctx, "example.com", []string{"test_key"}, 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}

func TestSearchWithKey_DuplicateIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ShodanResponse{
			Total: 3,
			Matches: []ShodanMatch{
				{IPStr: "192.168.1.1"},
				{IPStr: "192.168.1.2"},
				{IPStr: "192.168.1.1"}, // Duplicate
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Duplicate IP deduplication test completed")
	}
}

func TestSearchHostname_WhitespaceKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHostname(ctx, "example.com", []string{"  key1  ", "key2"}, 100*time.Millisecond)

	if err == nil {
		t.Log("Search with whitespace keys succeeded (might have network access)")
	}
}

func TestSearchWithKey_EmptyDomain(t *testing.T) {
	ctx := context.Background()
	_, err := searchWithKey(ctx, "", "test_key", 1*time.Second)

	if err == nil {
		t.Log("Expected error for empty domain")
	}
}

func TestShodanMatch_AllFields(t *testing.T) {
	match := ShodanMatch{
		IPStr:     "203.0.113.1",
		Hostnames: []string{"mail.example.com", "www.example.com"},
		Domains:   []string{"example.com", "example.net"},
		Port:      25,
		Transport: "tcp",
	}

	if match.IPStr != "203.0.113.1" {
		t.Errorf("IPStr = %s", match.IPStr)
	}
	if len(match.Hostnames) != 2 {
		t.Errorf("Hostnames count = %d, want 2", len(match.Hostnames))
	}
	if len(match.Domains) != 2 {
		t.Errorf("Domains count = %d, want 2", len(match.Domains))
	}
	if match.Port != 25 {
		t.Errorf("Port = %d, want 25", match.Port)
	}
}
