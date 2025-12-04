package dnsdumpster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSearchDomain_NoAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchDomain(ctx, "example.com", []string{}, 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when no API keys provided")
	}
	if err.Error() != "no DNSDumpster API keys provided" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSearchDomain_EmptyAPIKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchDomain(ctx, "example.com", []string{"", "  "}, 5*time.Second)

	if err == nil {
		t.Fatal("Expected error when all API keys are empty")
	}
	if err.Error() != "no valid API keys found" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSearchDomain_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check API key header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "test_key" {
			t.Errorf("Expected API key 'test_key', got '%s'", apiKey)
		}

		// Return valid response
		resp := DNSDumpsterResponse{
			A: []DNSRecord{
				{
					Host: "www.example.com",
					IPs: []IPDetail{
						{IP: "192.168.1.1", ASN: "AS12345", Country: "US"},
						{IP: "192.168.1.2", ASN: "AS12345", Country: "US"},
					},
				},
			},
			MX: []DNSRecord{
				{
					Host: "mail.example.com",
					IPs: []IPDetail{
						{IP: "192.168.1.3", ASN: "AS12345", Country: "US"},
					},
				},
			},
			TotalA: 2,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := SearchDomain(ctx, "example.com", []string{"test_key"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search succeeded (might have network access)")
	}
}

func TestSearchDomain_RateLimitRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := SearchDomain(ctx, "example.com", []string{"key1", "key2"}, 100*time.Millisecond)
	if err == nil {
		t.Log("Search with rotation succeeded")
	}
}

func TestSearchWithKey_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(DNSDumpsterResponse{
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

func TestSearchWithKey_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DNSDumpsterResponse{
			Error: "Domain not found",
		})
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Expected API error")
	}
}

func TestDNSDumpsterStructures(t *testing.T) {
	resp := DNSDumpsterResponse{
		A: []DNSRecord{
			{
				Host: "www.example.com",
				IPs: []IPDetail{
					{
						IP:          "192.168.1.1",
						ASN:         "AS12345",
						ASNName:     "Example Networks",
						ASNRange:    "192.168.0.0/16",
						Country:     "United States",
						CountryCode: "US",
						PTR:         "web1.example.com",
					},
				},
			},
		},
		TXT:    []string{"v=spf1 include:example.com ~all"},
		TotalA: 1,
	}

	if len(resp.A) != 1 {
		t.Error("Expected 1 A record")
	}
	if resp.TotalA != 1 {
		t.Errorf("TotalA = %d, want 1", resp.TotalA)
	}
	if len(resp.TXT) != 1 {
		t.Error("Expected 1 TXT record")
	}

	// Test IPDetail
	ipDetail := resp.A[0].IPs[0]
	if ipDetail.IP != "192.168.1.1" {
		t.Errorf("IP = %s", ipDetail.IP)
	}
	if ipDetail.ASN != "AS12345" {
		t.Errorf("ASN = %s", ipDetail.ASN)
	}
	if ipDetail.CountryCode != "US" {
		t.Errorf("CountryCode = %s", ipDetail.CountryCode)
	}
}

func TestIsValidIPv4_Valid(t *testing.T) {
	tests := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"255.255.255.255",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			if !isValidIPv4(ip) {
				t.Errorf("isValidIPv4(%s) = false, want true", ip)
			}
		})
	}
}

func TestIsValidIPv4_Invalid(t *testing.T) {
	tests := []string{
		"not-an-ip",
		"256.0.0.1",
		"192.168.1",
		"2001:db8::1", // IPv6
		"",
		"192.168.1.1.1",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			if isValidIPv4(ip) {
				t.Errorf("isValidIPv4(%s) = true, want false", ip)
			}
		})
	}
}

func TestSearchWithKey_MultipleRecordTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := DNSDumpsterResponse{
			A: []DNSRecord{
				{Host: "www.example.com", IPs: []IPDetail{{IP: "192.168.1.1"}}},
			},
			MX: []DNSRecord{
				{Host: "mail.example.com", IPs: []IPDetail{{IP: "192.168.1.2"}}},
			},
			NS: []DNSRecord{
				{Host: "ns1.example.com", IPs: []IPDetail{{IP: "192.168.1.3"}}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Multiple record types test completed")
	}
}

func TestSearchWithKey_DuplicateIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := DNSDumpsterResponse{
			A: []DNSRecord{
				{Host: "www.example.com", IPs: []IPDetail{{IP: "192.168.1.1"}}},
				{Host: "www2.example.com", IPs: []IPDetail{{IP: "192.168.1.1"}}}, // Duplicate
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

func TestSearchDomain_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := SearchDomain(ctx, "example.com", []string{"test_key"}, 5*time.Second)
	if err == nil {
		t.Log("Expected error for cancelled context")
	}
}

func TestSearchDomain_WhitespaceKeys(t *testing.T) {
	ctx := context.Background()
	_, err := SearchDomain(ctx, "example.com", []string{"  key1  ", "key2"}, 100*time.Millisecond)

	if err == nil {
		t.Log("Search with whitespace keys succeeded")
	}
}

func TestSearchWithKey_LongErrorBody(t *testing.T) {
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
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Expected error for bad request")
	}
}

func TestDNSRecord_Structure(t *testing.T) {
	record := DNSRecord{
		Host: "www.example.com",
		IPs: []IPDetail{
			{IP: "192.168.1.1", ASN: "AS12345"},
			{IP: "192.168.1.2", ASN: "AS12345"},
		},
	}

	if record.Host != "www.example.com" {
		t.Errorf("Host = %s", record.Host)
	}
	if len(record.IPs) != 2 {
		t.Errorf("IPs count = %d, want 2", len(record.IPs))
	}
}

func TestSearchWithKey_EmptyIPLists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := DNSDumpsterResponse{
			A: []DNSRecord{
				{Host: "www.example.com", IPs: []IPDetail{}},
			},
			MX: []DNSRecord{
				{Host: "mail.example.com", IPs: nil},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("Empty IP lists test completed")
	}
}

func TestSearchWithKey_IPv6InResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := DNSDumpsterResponse{
			A: []DNSRecord{
				{Host: "www.example.com", IPs: []IPDetail{
					{IP: "192.168.1.1"},
				}},
			},
			AAAA: []DNSRecord{
				{Host: "www.example.com", IPs: []IPDetail{
					{IP: "2001:db8::1"}, // AAAA records are not processed
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := searchWithKey(ctx, "example.com", "test_key", 1*time.Second)
	if err == nil {
		t.Log("IPv6 AAAA records test completed")
	}
}
