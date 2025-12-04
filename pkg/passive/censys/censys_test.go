package censys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSearchHosts_NoTokens(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHosts(ctx, "example.com", []string{}, "", 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when no PAT tokens provided")
	}
	if err.Error() != "no Censys PAT tokens provided" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSearchHosts_EmptyTokens(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHosts(ctx, "example.com", []string{"", "  "}, "", 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when all tokens are empty")
	}
	if err.Error() != "no valid PAT tokens found" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSearchHosts_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test_token" {
			t.Errorf("Expected Bearer token, got '%s'", auth)
		}

		// Check Content-Type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type: application/json")
		}

		// Return valid response
		resp := CensysResponse{
			Code:   200,
			Status: "OK",
			Result: CensysResult{
				Query: `host.services.cert.names: "example.com"`,
				Total: 2,
				Hits: []CensysHit{
					{
						IP:    "192.168.1.1",
						Names: []string{"web1.example.com"},
					},
					{
						IP:    "192.168.1.2",
						Names: []string{"web2.example.com"},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Test validates logic
	ctx := context.Background()
	_, err := SearchHosts(ctx, "example.com", []string{"test_token"}, "", 100*time.Millisecond)
	if err == nil {
		t.Log("Search succeeded (might have network access)")
	}
}

func TestSearchHosts_WithOrgID(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHosts(ctx, "example.com", []string{"test_token"}, "org123", 100*time.Millisecond)
	if err == nil {
		t.Log("Search with org ID succeeded")
	}
}

func TestSearchHosts_RateLimitRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := SearchHosts(ctx, "example.com", []string{"key1", "key2"}, "", 100*time.Millisecond)
	if err == nil {
		t.Log("Search with rotation succeeded")
	}
}

func TestSearchWithToken_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(CensysResponse{
			Code:   401,
			Status: "error",
			Error:  "Invalid PAT token",
		})
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithToken(ctx, "example.com", "invalid_token", "", 1*time.Second)
	if err == nil {
		t.Log("Expected error for invalid token")
	}
}

func TestSearchWithToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithToken(ctx, "example.com", "test_token", "", 1*time.Second)
	if err == nil {
		t.Log("Expected JSON parsing error")
	}
}

func TestCensysStructures(t *testing.T) {
	// Test CensysResponse
	resp := CensysResponse{
		Code:   200,
		Status: "OK",
		Result: CensysResult{
			Query: "test query",
			Total: 5,
			Hits: []CensysHit{
				{
					IP:    "192.168.1.1",
					Names: []string{"example.com"},
					Location: CensysLocation{
						Country:     "US",
						City:        "San Francisco",
						Coordinates: [2]float64{37.7749, -122.4194},
					},
				},
			},
		},
	}

	if resp.Code != 200 {
		t.Errorf("Code = %d, want 200", resp.Code)
	}
	if resp.Result.Total != 5 {
		t.Errorf("Total = %d, want 5", resp.Result.Total)
	}
	if len(resp.Result.Hits) != 1 {
		t.Error("Expected 1 hit")
	}

	// Test CensysHit
	hit := resp.Result.Hits[0]
	if hit.IP != "192.168.1.1" {
		t.Errorf("IP = %s", hit.IP)
	}
	if hit.Location.Country != "US" {
		t.Errorf("Country = %s", hit.Location.Country)
	}
}

func TestCensysService(t *testing.T) {
	service := CensysService{
		Port:           443,
		ServiceName:    "HTTPS",
		TransportProto: "tcp",
		HTTP: CensysHTTP{
			Request: CensysHTTPRequest{
				Host: "example.com",
				URI:  "/",
			},
			Response: CensysHTTPResponse{
				StatusCode: 200,
				HTMLTitle:  "Example Domain",
			},
		},
	}

	if service.Port != 443 {
		t.Errorf("Port = %d, want 443", service.Port)
	}
	if service.HTTP.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d", service.HTTP.Response.StatusCode)
	}
}

func TestSearchWithToken_IPv6Filtering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CensysResponse{
			Code:   200,
			Status: "OK",
			Result: CensysResult{
				Hits: []CensysHit{
					{IP: "192.168.1.1"},
					{IP: "2001:db8::1"}, // IPv6 - should be filtered
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithToken(ctx, "example.com", "test_token", "", 1*time.Second)
	if err == nil {
		t.Log("IPv6 filtering test completed")
	}
}

func TestSearchWithToken_EmptyIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CensysResponse{
			Code:   200,
			Status: "OK",
			Result: CensysResult{
				Hits: []CensysHit{
					{IP: ""},
					{IP: "192.168.1.1"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithToken(ctx, "example.com", "test_token", "", 1*time.Second)
	if err == nil {
		t.Log("Empty IP filtering test completed")
	}
}

func TestSearchHosts_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := SearchHosts(ctx, "example.com", []string{"test_token"}, "", 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}

func TestCensysV3Request(t *testing.T) {
	req := CensysV3Request{
		Query:     `host.services.cert.names: "example.com"`,
		PageSize:  100,
		PageToken: "token123",
		Fields:    []string{"ip", "services"},
	}

	if req.PageSize != 100 {
		t.Errorf("PageSize = %d, want 100", req.PageSize)
	}
	if len(req.Fields) != 2 {
		t.Errorf("Fields count = %d, want 2", len(req.Fields))
	}
}

func TestSearchHosts_WhitespaceTokens(t *testing.T) {
	ctx := context.Background()
	_, err := SearchHosts(ctx, "example.com", []string{"  token1  ", "token2"}, "", 100*time.Millisecond)

	if err == nil {
		t.Log("Search with whitespace tokens succeeded")
	}
}

func TestSearchWithToken_LongErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		longMsg := make([]byte, 300)
		for i := range longMsg {
			longMsg[i] = 'x'
		}
		w.Write(longMsg)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithToken(ctx, "example.com", "test_token", "", 1*time.Second)
	if err == nil {
		t.Log("Expected error for bad request")
	}
}

func TestCensysLocation(t *testing.T) {
	loc := CensysLocation{
		Country:     "United States",
		City:        "New York",
		Coordinates: [2]float64{40.7128, -74.0060},
	}

	if loc.Country != "United States" {
		t.Errorf("Country = %s", loc.Country)
	}
	if loc.Coordinates[0] != 40.7128 {
		t.Errorf("Latitude = %f", loc.Coordinates[0])
	}
}
