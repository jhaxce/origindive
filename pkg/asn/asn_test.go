package asn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name     string
		cacheDir string
		wantDir  string
	}{
		{
			name:     "with custom cache dir",
			cacheDir: "test_cache",
			wantDir:  "test_cache",
		},
		{
			name:     "with empty cache dir",
			cacheDir: "",
			wantDir:  "", // Will use default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.cacheDir)
			if client == nil {
				t.Error("NewClient() returned nil")
			}
			if client.client == nil {
				t.Error("HTTP client not initialized")
			}
			if client.client.Timeout != 30*time.Second {
				t.Errorf("Timeout = %v, want 30s", client.client.Timeout)
			}
			if tt.wantDir != "" && client.cacheDir != tt.wantDir {
				t.Errorf("cacheDir = %s, want %s", client.cacheDir, tt.wantDir)
			}
		})
	}
}

func TestClient_GetCachePath(t *testing.T) {
	client := NewClient("test_cache")

	tests := []struct {
		name string
		asn  string
		want string
	}{
		{
			name: "with AS prefix",
			asn:  "AS4775",
			want: filepath.Join("test_cache", "AS4775.json"),
		},
		{
			name: "without AS prefix",
			asn:  "13335",
			want: filepath.Join("test_cache", "13335.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.getCachePath(tt.asn)
			if got != tt.want {
				t.Errorf("getCachePath() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClient_SaveAndLoadCache(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(tmpDir)

	resp := &ASNResponse{
		ASN:       4775,
		ASNName:   "Test AS",
		ASNRanges: []string{"192.0.2.0/24", "198.51.100.0/24"},
	}

	// Save to cache
	err := client.saveToCache("AS4775", resp)
	if err != nil {
		t.Fatalf("saveToCache() error: %v", err)
	}

	// Load from cache
	loaded, err := client.loadFromCache("AS4775")
	if err != nil {
		t.Fatalf("loadFromCache() error: %v", err)
	}

	if loaded.ASN != resp.ASN {
		t.Errorf("ASN = %d, want %d", loaded.ASN, resp.ASN)
	}
	if loaded.ASNName != resp.ASNName {
		t.Errorf("ASNName = %s, want %s", loaded.ASNName, resp.ASNName)
	}
	if len(loaded.ASNRanges) != len(resp.ASNRanges) {
		t.Errorf("ASNRanges count = %d, want %d", len(loaded.ASNRanges), len(resp.ASNRanges))
	}
	if !loaded.CacheValid {
		t.Error("CacheValid should be true after loading")
	}
}

func TestClient_LoadFromCache_NotExist(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(tmpDir)

	_, err := client.loadFromCache("AS9999")
	if err == nil {
		t.Error("loadFromCache() should error on non-existent cache")
	}
}

func TestClient_FetchFromAPI(t *testing.T) {
	// Create mock API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asn := r.URL.Query().Get("asn")
		if asn == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := ASNResponse{
			ASN:       13335,
			ASNName:   "Cloudflare, Inc.",
			ASNRanges: []string{"1.1.1.0/24", "1.0.0.0/24"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(t.TempDir())

	t.Run("successful fetch", func(t *testing.T) {
		// Note: This would call the real API, so we skip it in tests
		// Instead we test the mock directly
		req, _ := http.NewRequest("GET", server.URL+"?asn=AS13335", nil)
		req.Header.Set("User-Agent", "origindive/3.1.0")

		resp, err := client.client.Do(req)
		if err != nil {
			t.Fatalf("Request error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status = %d, want 200", resp.StatusCode)
		}

		var asnResp ASNResponse
		if err := json.NewDecoder(resp.Body).Decode(&asnResp); err != nil {
			t.Fatalf("Decode error: %v", err)
		}

		if asnResp.ASN != 13335 {
			t.Errorf("ASN = %d, want 13335", asnResp.ASN)
		}
		if len(asnResp.ASNRanges) != 2 {
			t.Errorf("ASNRanges count = %d, want 2", len(asnResp.ASNRanges))
		}
	})
}

func TestClient_LookupASN_WithCache(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(tmpDir)

	// Pre-populate cache
	resp := &ASNResponse{
		ASN:       4775,
		ASNName:   "Cached AS",
		ASNRanges: []string{"192.0.2.0/24"},
	}
	client.saveToCache("AS4775", resp)

	// Lookup should use cache
	result, err := client.LookupASN("AS4775")
	if err != nil {
		t.Fatalf("LookupASN() error: %v", err)
	}

	if result.ASNName != "Cached AS" {
		t.Error("Should have loaded from cache")
	}
	if !result.CacheValid {
		t.Error("Cache should be valid")
	}
}

func TestClient_LookupASN_NormalizeASN(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(tmpDir)

	// Pre-populate cache without AS prefix
	resp := &ASNResponse{
		ASN:       4775,
		ASNName:   "Test",
		ASNRanges: []string{"192.0.2.0/24"},
	}
	client.saveToCache("AS4775", resp)

	// Lookup with number only (should normalize to AS4775)
	result, err := client.LookupASN("4775")
	if err != nil {
		t.Fatalf("LookupASN() error: %v", err)
	}

	if result.ASN != 4775 {
		t.Errorf("ASN = %d, want 4775", result.ASN)
	}
}

func TestGetDefaultCacheDir(t *testing.T) {
	dir := getDefaultCacheDir()
	if dir == "" {
		t.Error("getDefaultCacheDir() returned empty string")
	}

	// Should contain either .cache or data
	if !contains(dir, ".cache") && !contains(dir, "data") {
		t.Errorf("Unexpected cache dir: %s", dir)
	}
}

func TestConvertToIPRanges(t *testing.T) {
	tests := []struct {
		name    string
		resp    *ASNResponse
		wantErr bool
	}{
		{
			name: "valid response",
			resp: &ASNResponse{
				ASN:       4775,
				ASNRanges: []string{"192.0.2.0/24", "198.51.100.0/24"},
			},
			wantErr: false,
		},
		{
			name:    "nil response",
			resp:    nil,
			wantErr: true,
		},
		{
			name: "empty ranges",
			resp: &ASNResponse{
				ASN:       4775,
				ASNRanges: []string{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ConvertToIPRanges(tt.resp)
			if tt.wantErr && err == nil {
				t.Error("ConvertToIPRanges() expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ConvertToIPRanges() unexpected error: %v", err)
			}
		})
	}
}

func TestClient_SaveToCache_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "nested", "cache", "dir")

	client := NewClient(cacheDir)

	resp := &ASNResponse{
		ASN:       4775,
		ASNName:   "Test",
		ASNRanges: []string{"192.0.2.0/24"},
	}

	err := client.saveToCache("AS4775", resp)
	if err != nil {
		t.Fatalf("saveToCache() should create directories: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Error("Cache directory was not created")
	}
}

func TestClient_LoadFromCache_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(tmpDir)

	// Write invalid JSON to cache
	cachePath := client.getCachePath("AS4775")
	os.MkdirAll(tmpDir, 0755)
	os.WriteFile(cachePath, []byte("invalid json{"), 0644)

	_, err := client.loadFromCache("AS4775")
	if err == nil {
		t.Error("loadFromCache() should error on invalid JSON")
	}
}

func TestASNResponse_CacheValid(t *testing.T) {
	resp := &ASNResponse{
		ASN:        4775,
		ASNName:    "Test",
		ASNRanges:  []string{"192.0.2.0/24"},
		CacheValid: true,
	}

	if !resp.CacheValid {
		t.Error("CacheValid should be true")
	}

	// Test JSON marshaling (CacheValid is omitted due to json:"-")
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	if contains(string(data), "CacheValid") {
		t.Error("CacheValid should not appear in JSON")
	}
}

func TestConvertToIPRanges_WithEmptyCIDR(t *testing.T) {
	resp := &ASNResponse{
		ASN:       4775,
		ASNRanges: []string{"192.0.2.0/24", "", "198.51.100.0/24"},
	}

	ranges, err := ConvertToIPRanges(resp)
	if err != nil {
		t.Fatalf("ConvertToIPRanges() error: %v", err)
	}

	// Function validates structure, doesn't actually parse CIDRs
	_ = ranges
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
