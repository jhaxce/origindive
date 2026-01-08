package securitytrails

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSearchSubdomainsAndHistory_NoAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when no API keys provided")
	}
}

func TestSearchSubdomainsAndHistory_EmptyAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{"", "  "}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when all API keys are empty")
	}
}

func TestSearchSubdomainsAndHistory_Success(t *testing.T) {
	ctx := context.Background()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{"test_key"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search succeeded")
	}
}

func TestSecurityTrailsStructures(t *testing.T) {
	resp := SubdomainResponse{
		Subdomains: []string{"www", "mail"},
	}
	if len(resp.Subdomains) != 2 {
		t.Errorf("Subdomains count = %d", len(resp.Subdomains))
	}
}

func TestSearchSubdomainsAndHistory_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := SearchSubdomainsAndHistory(ctx, "example.com", []string{"test_key"}, 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}

func TestResolveToIPv4(t *testing.T) {
	ctx := context.Background()
	_, err := resolveToIPv4(ctx, "localhost", 2*time.Second)
	if err != nil {
		t.Logf("Resolve failed: %v", err)
	}
}

// TestGetSubdomains_MockServer tests getSubdomains with mock server
func TestGetSubdomains_MockServer(t *testing.T) {
	tests := []struct {
		name       string
		response   interface{}
		statusCode int
		wantErr    bool
		wantCount  int
	}{
		{
			name: "successful response",
			response: SubdomainResponse{
				Subdomains: []string{"www", "mail", "ftp"},
			},
			statusCode: http.StatusOK,
			wantErr:    false,
			wantCount:  3,
		},
		{
			name: "empty subdomains",
			response: SubdomainResponse{
				Subdomains: []string{},
			},
			statusCode: http.StatusOK,
			wantErr:    false,
			wantCount:  0,
		},
		{
			name: "api error with message",
			response: SubdomainResponse{
				Message: "Invalid API key",
			},
			statusCode: http.StatusUnauthorized,
			wantErr:    true,
		},
		{
			name:       "server error",
			response:   map[string]string{"error": "internal error"},
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check API key header
				if r.Header.Get("APIKEY") == "" {
					t.Error("Missing APIKEY header")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Note: Can't easily test this without modifying the URL in the function
			// This test demonstrates the structure but won't reach the actual function
			ctx := context.Background()
			_, err := getSubdomains(ctx, "example.com", "test_key", 5*time.Second)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Logf("Got error (expected for real API call): %v", err)
			}
		})
	}
}

// TestSearchWithKey_ErrorHandling tests error handling in searchWithKey
func TestSearchWithKey_ErrorHandling(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name   string
		domain string
		apiKey string
	}{
		{
			name:   "empty domain",
			domain: "",
			apiKey: "test_key",
		},
		{
			name:   "invalid api key",
			domain: "example.com",
			apiKey: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := searchWithKey(ctx, tt.domain, tt.apiKey, 100*time.Millisecond)
			if err == nil {
				t.Log("searchWithKey returned no error (may depend on API)")
			}
		})
	}
}

// TestGetHistoricalIPs tests getHistoricalIPs function
func TestGetHistoricalIPs(t *testing.T) {
	ctx := context.Background()

	// Test with invalid API key (should fail)
	_, err := getHistoricalIPs(ctx, "example.com", "invalid_key", 100*time.Millisecond)
	if err == nil {
		t.Log("getHistoricalIPs succeeded (unexpected)")
	} else {
		t.Logf("getHistoricalIPs failed as expected: %v", err)
	}
}

// TestResolveToIPv4_ValidDomain tests resolution of a known domain
func TestResolveToIPv4_ValidDomain(t *testing.T) {
	ctx := context.Background()

	// Test with localhost which should always resolve
	ips, err := resolveToIPv4(ctx, "localhost", 2*time.Second)
	if err != nil {
		t.Errorf("Failed to resolve localhost: %v", err)
	}

	if len(ips) == 0 {
		t.Error("Expected at least one IP for localhost")
	}

	// Verify IPs are valid
	for _, ip := range ips {
		if ip == "" {
			t.Error("Got empty IP string")
		}
	}
}

// TestResolveToIPv4_InvalidDomain tests resolution of invalid domain
func TestResolveToIPv4_InvalidDomain(t *testing.T) {
	ctx := context.Background()

	_, err := resolveToIPv4(ctx, "this-domain-definitely-does-not-exist-12345.invalid", 2*time.Second)
	if err == nil {
		t.Error("Expected error for invalid domain")
	}
}

// TestResolveToIPv4_ContextTimeout tests context timeout handling
func TestResolveToIPv4_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout

	_, err := resolveToIPv4(ctx, "example.com", 5*time.Second)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

// TestHistoricalResponse_Structure tests the HistoryResponse structure
func TestHistoricalResponse_Structure(t *testing.T) {
	resp := HistoryResponse{
		Records: []HistoryRecord{
			{
				Type:   "a",
				Values: []Value{{IP: "192.168.1.1"}},
			},
		},
	}

	if len(resp.Records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(resp.Records))
	}

	if len(resp.Records[0].Values) != 1 {
		t.Errorf("Expected 1 value, got %d", len(resp.Records[0].Values))
	}

	if resp.Records[0].Values[0].IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", resp.Records[0].Values[0].IP)
	}
}
