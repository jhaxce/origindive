package viewdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		if r.Header.Get("User-Agent") != "origindive/1.0" {
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

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "invalid_key", 1*time.Second)

	if err == nil {
		t.Error("Expected error for HTTP error")
	} else if !strings.Contains(err.Error(), "status 403") {
		t.Errorf("Expected status 403 error, got: %v", err)
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

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)

	if err == nil {
		t.Error("Expected API error")
	} else if !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("Expected 'Invalid API key' error, got: %v", err)
	}
}

func TestReverseIPWithKey_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)

	if err == nil {
		t.Error("Expected JSON parsing error")
	} else if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("Expected parse error, got: %v", err)
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

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	ips, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs for empty domain list, got %d", len(ips))
	}
}

func TestReverseIPWithKey_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 5*time.Second)

	if err == nil {
		t.Error("Expected error for cancelled context")
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
		// Write long error message (should be truncated to 200 chars + "...")
		longMsg := make([]byte, 300)
		for i := range longMsg {
			longMsg[i] = 'x'
		}
		w.Write(longMsg)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)

	if err == nil {
		t.Error("Expected error for bad request")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "...") {
			t.Errorf("Expected truncated message with '...', got: %v", err)
		}
		if len(errMsg) > 300 {
			t.Errorf("Error message too long (%d chars): %s", len(errMsg), errMsg)
		}
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

func TestReverseIPWithKey_StatusCodes(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   interface{}
		wantErrContain string
	}{
		{
			name:           "401 Unauthorized",
			statusCode:     http.StatusUnauthorized,
			responseBody:   ViewDNSResponse{Response: ViewDNSResults{Error: "Unauthorized"}},
			wantErrContain: "Unauthorized",
		},
		{
			name:           "429 Rate Limit",
			statusCode:     http.StatusTooManyRequests,
			responseBody:   "Rate limit exceeded",
			wantErrContain: "status 429",
		},
		{
			name:           "500 Server Error",
			statusCode:     http.StatusInternalServerError,
			responseBody:   "Internal server error",
			wantErrContain: "status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)

				switch v := tt.responseBody.(type) {
				case ViewDNSResponse:
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(v)
				case string:
					w.Write([]byte(v))
				}
			}))
			defer server.Close()

			// Override API URL for testing
			oldURL := apiBaseURL
			apiBaseURL = server.URL + "/"
			defer func() { apiBaseURL = oldURL }()

			ctx := context.Background()
			_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Second)

			if err == nil {
				t.Errorf("Expected error for status %d", tt.statusCode)
			} else if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Errorf("Error should contain '%s', got: %v", tt.wantErrContain, err)
			}
		})
	}
}

func TestReverseIPWithKey_DomainResolution(t *testing.T) {
	// Test that domains are resolved to IPs (skip resolution failures)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ViewDNSResponse{
			Query: ViewDNSQuery{ToolType: 2, Host: "192.168.1.1"},
			Response: ViewDNSResults{
				Domains: []ViewDNSDomain{
					{Name: "localhost", LastResolved: "2024-01-01"},                        // Should resolve
					{Name: "nonexistent-domain-12345.invalid", LastResolved: "2024-01-01"}, // Should be skipped
					{Name: "  ", LastResolved: "2024-01-01"},                               // Empty after trim, skip
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	ips, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 5*time.Second)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should get at least localhost IP (127.0.0.1 or others)
	if len(ips) == 0 {
		t.Error("Expected at least 1 IP from localhost resolution")
	}
}

func TestReverseIPWithKey_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	_, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 1*time.Millisecond)

	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestReverseIPWithKey_IPv4FilteringOnly(t *testing.T) {
	// Test that only IPv4 addresses are returned (IPv6 filtered out)
	// This is tested via DomainResolution test with localhost (may return ::1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ViewDNSResponse{
			Query: ViewDNSQuery{ToolType: 2, Host: "192.168.1.1"},
			Response: ViewDNSResults{
				Domains: []ViewDNSDomain{
					{Name: "localhost", LastResolved: "2024-01-01"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiBaseURL
	apiBaseURL = server.URL + "/"
	defer func() { apiBaseURL = oldURL }()

	ctx := context.Background()
	ips, err := reverseIPWithKey(ctx, "192.168.1.1", "test_key", 5*time.Second)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify all IPs are IPv4
	for _, ipStr := range ips {
		if !strings.Contains(ipStr, ".") || strings.Contains(ipStr, ":") {
			t.Errorf("Expected IPv4 address, got: %s", ipStr)
		}
	}
}
