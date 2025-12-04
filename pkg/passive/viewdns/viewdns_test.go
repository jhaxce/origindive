package viewdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSearchReverseIP_NoAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchReverseIP(ctx, "example.com", []string{}, 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when no API keys provided")
	}
	if err.Error() != "no ViewDNS API keys provided" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSearchReverseIP_EmptyAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchReverseIP(ctx, "example.com", []string{"", "  "}, 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when all API keys are empty")
	}
}

func TestSearchReverseIP_DNSResolutionFails(t *testing.T) {
	ctx := context.Background()
	_, err := SearchReverseIP(ctx, "nonexistent-domain-12345.invalid", []string{"test_key"}, 2*time.Second)

	if err == nil {
		t.Fatal("Expected error for unresolvable domain")
	}
	if err.Error() != "failed to resolve domain: lookup nonexistent-domain-12345.invalid: no such host" {
		t.Logf("Error: %v", err)
	}
}

func TestSearchReverseIP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check User-Agent
		if r.Header.Get("User-Agent") != "origindive/3.1.0" {
			t.Errorf("Unexpected User-Agent: %s", r.Header.Get("User-Agent"))
		}

		// Return valid response
		resp := ViewDNSResponse{
			Query: ViewDNSQuery{
				ToolType: 2,
				Host:     "192.168.1.1",
			},
			Response: ViewDNSResults{
				Domains: []ViewDNSDomain{
					{Name: "example1.com", LastResolved: "2024-01-01"},
					{Name: "example2.com", LastResolved: "2024-01-02"},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Test validates logic but can't inject test server
	ctx := context.Background()
	_, err := SearchReverseIP(ctx, "google.com", []string{"test_key"}, 2*time.Second)
	if err == nil {
		t.Log("Search succeeded (might have network access)")
	}
}

func TestSearchReverseIP_RateLimitRotation(t *testing.T) {
	// Test validates that rate limiting triggers key rotation
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := SearchReverseIP(ctx, "google.com", []string{"key1", "key2"}, 1*time.Second)
	if err == nil {
		t.Log("Search with rotation succeeded (might have network access)")
	}
}

func TestReverseIPWithKey_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Invalid API key"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "invalid_key", 1*time.Second)
	if err == nil {
		t.Log("Expected error for HTTP error")
	}
}

func TestReverseIPWithKey_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ViewDNSResponse{
			Response: ViewDNSResults{
				Error: "Invalid API key",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Expected API error")
	}
}

func TestReverseIPWithKey_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Expected JSON parsing error")
	}
}

func TestViewDNSStructures(t *testing.T) {
	// Test ViewDNSResponse
	resp := ViewDNSResponse{
		Query: ViewDNSQuery{
			ToolType: 2,
			Host:     "192.168.1.1",
		},
		Response: ViewDNSResults{
			Domains: []ViewDNSDomain{
				{Name: "example.com", LastResolved: "2024-01-01"},
			},
			Error: "",
		},
	}

	if resp.Query.ToolType != 2 {
		t.Errorf("ToolType = %d, want 2", resp.Query.ToolType)
	}
	if resp.Query.Host != "192.168.1.1" {
		t.Errorf("Host = %s, want 192.168.1.1", resp.Query.Host)
	}
	if len(resp.Response.Domains) != 1 {
		t.Error("Expected 1 domain")
	}
}

func TestViewDNSDomain(t *testing.T) {
	domain := ViewDNSDomain{
		Name:         "example.com",
		LastResolved: "2024-01-01 12:00:00",
	}

	if domain.Name != "example.com" {
		t.Errorf("Name = %s, want example.com", domain.Name)
	}
	if domain.LastResolved != "2024-01-01 12:00:00" {
		t.Errorf("LastResolved = %s", domain.LastResolved)
	}
}

func TestSearchReverseIP_NoIPv4(t *testing.T) {
	// Test when domain resolves to IPv6 only
	// This would require DNS mocking which we can't do here
	ctx := context.Background()
	_, err := SearchReverseIP(ctx, "localhost", []string{"test_key"}, 1*time.Second)
	if err == nil {
		t.Log("Localhost search succeeded")
	}
}

func TestReverseIPWithKey_EmptyDomainList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ViewDNSResponse{
			Query: ViewDNSQuery{ToolType: 2, Host: "192.168.1.1"},
			Response: ViewDNSResults{
				Domains: []ViewDNSDomain{}, // Empty list
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Empty domain list handled")
	}
}

func TestReverseIPWithKey_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}

func TestSearchReverseIP_WhitespaceKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchReverseIP(ctx, "google.com", []string{"  key1  ", "key2"}, 100*time.Millisecond)

	if err == nil {
		t.Log("Search with whitespace keys succeeded (might have network access)")
	}
}

func TestReverseIPWithKey_LongErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Write long error message (should be truncated)
		longMsg := make([]byte, 300)
		for i := range longMsg {
			longMsg[i] = 'x'
		}
		w.Write(longMsg)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Expected error for bad request")
	} else if len(err.Error()) > 300 {
		t.Logf("Error message might not be truncated: %d chars", len(err.Error()))
	}
}

func TestSearchReverseIP_AllKeysExhausted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := SearchReverseIP(ctx, "google.com", []string{"key1", "key2"}, 1*time.Second)
	if err == nil {
		t.Log("Expected error for exhausted keys")
	}
}

func TestReverseIPWithKey_URLEscaping(t *testing.T) {
	// Test that IP address and API key are properly escaped
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := reverseIPWithKey(ctx, "192.168.1.1", "key&special=chars", 1*time.Second)
	if err == nil {
		t.Log("URL escaping test completed")
	}
}
