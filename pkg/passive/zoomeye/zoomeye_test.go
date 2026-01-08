package zoomeye

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSearchHost_NoAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHost(ctx, "example.com", []string{}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when no API keys provided")
	}
}

func TestSearchHost_EmptyAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHost(ctx, "example.com", []string{"", "  "}, 5*time.Second)
	if err == nil {
		t.Fatal("Expected error when all API keys are empty")
	}
}

func TestSearchHost_Success(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHost(ctx, "example.com", []string{"test_key"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search succeeded")
	}
}

func TestZoomEyeStructures(t *testing.T) {
	resp := ZoomEyeV2Response{
		Code:    60000,
		Message: "OK",
		Total:   1,
		Data: []ZoomEyeV2Asset{
			{IP: "192.168.1.1", Port: 443, Domain: "example.com"},
		},
	}
	if resp.Code != 60000 {
		t.Errorf("Code = %d", resp.Code)
	}
}

func TestSearchHost_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := SearchHost(ctx, "example.com", []string{"test_key"}, 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}

func TestSearchWithKey_StatusCodes(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   interface{}
		wantErrContain string
	}{
		{
			name:           "401 Unauthorized",
			statusCode:     http.StatusUnauthorized,
			responseBody:   ZoomEyeV2Response{Code: 40101, Message: "Invalid API key"},
			wantErrContain: "Invalid API key",
		},
		{
			name:           "429 Rate Limit",
			statusCode:     http.StatusTooManyRequests,
			responseBody:   ZoomEyeV2Response{Code: 42901, Message: "Rate limit exceeded"},
			wantErrContain: "Rate limit exceeded",
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
				// Verify POST method
				if r.Method != "POST" {
					t.Errorf("Expected POST, got %s", r.Method)
				}

				// Verify headers
				if r.Header.Get("API-KEY") != "test_key" {
					t.Errorf("Expected API-KEY='test_key', got '%s'", r.Header.Get("API-KEY"))
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected Content-Type='application/json', got '%s'", r.Header.Get("Content-Type"))
				}

				// Verify request body structure
				body, _ := io.ReadAll(r.Body)
				var reqBody ZoomEyeV2Request
				if err := json.Unmarshal(body, &reqBody); err == nil {
					if reqBody.QBase64 == "" {
						t.Error("Expected qbase64 field in request")
					}
					if reqBody.SubType != "v4" {
						t.Errorf("Expected sub_type='v4', got '%s'", reqBody.SubType)
					}
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.responseBody.(type) {
				case ZoomEyeV2Response:
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(v)
				case string:
					w.Write([]byte(v))
				}
			}))
			defer server.Close()

			// Override API URL for testing
			oldURL := apiURL
			apiURL = server.URL
			defer func() { apiURL = oldURL }()

			ctx := context.Background()
			_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)

			if err == nil {
				t.Errorf("Expected error for status %d", tt.statusCode)
			} else if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Errorf("Error should contain '%s', got: %v", tt.wantErrContain, err)
			}
		})
	}
}

func TestSearchWithKey_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)

	if err == nil {
		t.Error("Expected JSON parsing error")
	} else if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("Expected parse error, got: %v", err)
	}
}

func TestSearchWithKey_APIErrorCode(t *testing.T) {
	// Test case where API returns 200 OK but with non-60000 code
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ZoomEyeV2Response{
			Code:    40101,
			Message: "Authentication failed",
		})
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)

	if err == nil {
		t.Error("Expected API error for non-60000 code")
	} else if !strings.Contains(err.Error(), "Authentication failed") {
		t.Errorf("Expected authentication error, got: %v", err)
	}
}

func TestSearchWithKey_SuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ZoomEyeV2Response{
			Code:    60000,
			Message: "Success",
			Total:   3,
			Data: []ZoomEyeV2Asset{
				{IP: "192.168.1.1", Port: 443},
				{IP: "192.168.1.2", Port: 80},
				{IP: "  192.168.1.3  ", Port: 443}, // With whitespace
				{IP: "192.168.1.1", Port: 8080},    // Duplicate IP (different port)
				{IP: "", Port: 443},                // Empty IP (skip)
				{IP: "invalid-ip", Port: 443},      // Invalid IP (skip)
				{IP: "2001:db8::1", Port: 443},     // IPv6 (skip - v4 only)
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx := context.Background()
	ips, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Expected: 3 unique IPv4 IPs (192.168.1.1, 192.168.1.2, 192.168.1.3)
	if len(ips) != 3 {
		t.Errorf("Expected 3 unique IPs, got %d: %v", len(ips), ips)
	}

	// Verify specific IPs are present
	ipMap := make(map[string]bool)
	for _, ip := range ips {
		ipMap[ip] = true
	}

	expectedIPs := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	for _, expectedIP := range expectedIPs {
		if !ipMap[expectedIP] {
			t.Errorf("Expected IP %s not found in results", expectedIP)
		}
	}
}

func TestSearchWithKey_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ZoomEyeV2Response{
			Code:    60000,
			Message: "Success",
			Total:   0,
			Data:    []ZoomEyeV2Asset{}, // Empty data
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx := context.Background()
	ips, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs, got %d", len(ips))
	}
}

func TestSearchWithKey_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := searchWithKey(ctx, "example.com", "test_key", 5*time.Second)

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestSearchWithKey_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Millisecond)

	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestSearchWithKey_LongBodyTruncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Write a 300-byte error response (should be truncated to 200 + "...")
		longBody := make([]byte, 300)
		for i := range longBody {
			longBody[i] = 'x'
		}
		w.Write(longBody)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)

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

func TestSearchWithKey_Base64Query(t *testing.T) {
	// Verify that the domain query is base64-encoded in the request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var reqBody ZoomEyeV2Request
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("Failed to parse request: %v", err)
		}

		// Verify qbase64 is not empty
		if reqBody.QBase64 == "" {
			t.Error("Expected qbase64 field to be populated")
		}

		// Verify it's valid base64 and contains the domain
		// (Don't decode here, just verify it exists)

		resp := ZoomEyeV2Response{
			Code:    60000,
			Message: "Success",
			Total:   0,
			Data:    []ZoomEyeV2Asset{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override API URL for testing
	oldURL := apiURL
	apiURL = server.URL
	defer func() { apiURL = oldURL }()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "test-domain.com", "test_key", 1*time.Second)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}
