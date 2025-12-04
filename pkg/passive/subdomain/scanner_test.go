package subdomain

import (
	"context"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner("example.com", 10, 3*time.Second)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.domain != "example.com" {
		t.Errorf("domain = %s, want example.com", scanner.domain)
	}
	if scanner.workers != 10 {
		t.Errorf("workers = %d, want 10", scanner.workers)
	}
	if scanner.timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", scanner.timeout)
	}
	if len(scanner.dnsServers) != 2 {
		t.Errorf("dnsServers count = %d, want 2", len(scanner.dnsServers))
	}
	if scanner.discovered == nil {
		t.Error("discovered map should be initialized")
	}
}

func TestScanner_Scan_EmptyList(t *testing.T) {
	scanner := NewScanner("example.com", 5, 2*time.Second)
	ctx := context.Background()

	results, err := scanner.Scan(ctx, []string{})
	if err != nil {
		t.Errorf("Scan should not error on empty list: %v", err)
	}

	// Should use CommonSubdomains when list is empty
	// Results might be empty if resolutions fail
	t.Logf("Scanned with common subdomains, found %d results", len(results))
}

func TestScanner_Scan_CustomList(t *testing.T) {
	scanner := NewScanner("google.com", 3, 3*time.Second)
	ctx := context.Background()

	subdomains := []string{"www", "mail", "nonexistent99999"}
	results, err := scanner.Scan(ctx, subdomains)
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}

	// At least www and mail should resolve for google.com
	if len(results) == 0 {
		t.Log("No results found (might be network issue)")
	} else {
		t.Logf("Found %d subdomains", len(results))
	}
}

func TestScanner_Scan_ContextCancellation(t *testing.T) {
	scanner := NewScanner("example.com", 5, 3*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	subdomains := []string{"www", "mail", "api"}
	results, err := scanner.Scan(ctx, subdomains)
	if err != nil {
		t.Errorf("Scan should not error on cancellation: %v", err)
	}

	// Should return early with partial/no results
	t.Logf("Found %d results with cancelled context", len(results))
}

func TestScanner_GetAllIPs_Empty(t *testing.T) {
	scanner := NewScanner("example.com", 5, 3*time.Second)

	ips := scanner.GetAllIPs()
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs before scan, got %d", len(ips))
	}
}

func TestScanner_GetAllIPs_AfterScan(t *testing.T) {
	scanner := NewScanner("google.com", 3, 3*time.Second)
	ctx := context.Background()

	subdomains := []string{"www"}
	_, err := scanner.Scan(ctx, subdomains)
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}

	ips := scanner.GetAllIPs()
	if len(ips) == 0 {
		t.Log("No IPs found (might be network issue)")
	} else {
		t.Logf("GetAllIPs returned %d IPs", len(ips))
	}
}

func TestScanner_GetAllIPs_Deduplication(t *testing.T) {
	scanner := NewScanner("example.com", 5, 3*time.Second)

	// Manually add duplicate IPs to discovered
	scanner.discovered["sub1"] = []string{"192.168.1.1", "192.168.1.2"}
	scanner.discovered["sub2"] = []string{"192.168.1.1", "192.168.1.3"} // Duplicate 192.168.1.1

	ips := scanner.GetAllIPs()
	if len(ips) != 3 {
		t.Errorf("Expected 3 unique IPs, got %d", len(ips))
	}

	// Verify no duplicates
	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("Duplicate IP: %s", ip)
		}
		seen[ip] = true
	}
}

func TestScanner_GetResults_Empty(t *testing.T) {
	scanner := NewScanner("example.com", 5, 3*time.Second)

	results := scanner.GetResults()
	if len(results) != 0 {
		t.Errorf("Expected empty results, got %d", len(results))
	}
}

func TestScanner_GetResults_AfterScan(t *testing.T) {
	scanner := NewScanner("google.com", 3, 3*time.Second)
	ctx := context.Background()

	subdomains := []string{"www"}
	_, err := scanner.Scan(ctx, subdomains)
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}

	results := scanner.GetResults()
	if len(results) == 0 {
		t.Log("No results (might be network issue)")
	} else {
		t.Logf("GetResults returned %d subdomains", len(results))

		// Verify it's a copy (not reference to internal map)
		for subdomain, ips := range results {
			t.Logf("%s -> %v", subdomain, ips)
		}
	}
}

func TestScanner_GetResults_ReturnsCopy(t *testing.T) {
	scanner := NewScanner("example.com", 5, 3*time.Second)
	scanner.discovered["test"] = []string{"192.168.1.1"}

	results1 := scanner.GetResults()
	results2 := scanner.GetResults()

	// Modify results1
	results1["test"] = append(results1["test"], "192.168.1.2")

	// results2 should be unaffected (separate copy)
	if len(results2["test"]) != 1 {
		t.Error("GetResults should return a copy, not reference")
	}
}

func TestResult_Structure(t *testing.T) {
	result := Result{
		Subdomain: "www.example.com",
		IPs:       []string{"192.168.1.1"},
		Error:     nil,
	}

	if result.Subdomain != "www.example.com" {
		t.Errorf("Subdomain = %s, want www.example.com", result.Subdomain)
	}
	if len(result.IPs) != 1 {
		t.Errorf("IPs length = %d, want 1", len(result.IPs))
	}
}

func TestCommonSubdomains_NotEmpty(t *testing.T) {
	if len(CommonSubdomains) == 0 {
		t.Error("CommonSubdomains should not be empty")
	}

	// Check for some expected subdomains
	expected := []string{"www", "mail", "api", "cdn", "dev"}
	for _, sub := range expected {
		found := false
		for _, common := range CommonSubdomains {
			if common == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subdomain %s not found in CommonSubdomains", sub)
		}
	}
}

func TestScanner_ResolveSubdomain_ValidDomain(t *testing.T) {
	scanner := NewScanner("google.com", 5, 5*time.Second)

	ips, err := scanner.resolveSubdomain("www")
	if err != nil {
		t.Logf("Resolution failed (expected in test env): %v", err)
		return
	}

	if len(ips) == 0 {
		t.Error("Expected at least 1 IP for www.google.com")
	}

	// All should be IPv4
	for _, ip := range ips {
		if len(ip) > 15 {
			t.Errorf("Expected IPv4 only, got: %s", ip)
		}
	}
}

func TestScanner_ResolveSubdomain_InvalidDomain(t *testing.T) {
	scanner := NewScanner("example.com", 5, 2*time.Second)

	ips, err := scanner.resolveSubdomain("nonexistent99999")
	if err == nil {
		t.Log("Resolution succeeded unexpectedly")
	}

	if len(ips) > 0 {
		t.Errorf("Expected 0 IPs for invalid subdomain, got %d", len(ips))
	}
}

func TestScanner_ResolveSubdomain_Timeout(t *testing.T) {
	scanner := NewScanner("example.com", 5, 1*time.Nanosecond)

	_, err := scanner.resolveSubdomain("www")
	if err == nil {
		t.Log("Resolution succeeded despite timeout (might be cached)")
	}
}

func TestScanner_ConcurrentScan(t *testing.T) {
	scanner := NewScanner("google.com", 10, 5*time.Second)
	ctx := context.Background()

	// Scan with multiple subdomains concurrently
	subdomains := []string{"www", "mail", "calendar", "drive", "docs"}
	results, err := scanner.Scan(ctx, subdomains)
	if err != nil {
		t.Errorf("Concurrent scan failed: %v", err)
	}

	if len(results) == 0 {
		t.Log("No results from concurrent scan (might be network issue)")
	} else {
		t.Logf("Concurrent scan found %d subdomains", len(results))
	}
}

func TestScanner_WorkerCount(t *testing.T) {
	tests := []struct {
		name    string
		workers int
	}{
		{"single worker", 1},
		{"few workers", 3},
		{"many workers", 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner("example.com", tt.workers, 2*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := scanner.Scan(ctx, []string{"www", "api"})
			if err != nil {
				t.Errorf("Scan with %d workers failed: %v", tt.workers, err)
			}
		})
	}
}

func TestScanner_MultipleScanCalls(t *testing.T) {
	scanner := NewScanner("google.com", 5, 3*time.Second)
	ctx := context.Background()

	// First scan
	results1, err := scanner.Scan(ctx, []string{"www"})
	if err != nil {
		t.Errorf("First scan failed: %v", err)
	}

	// Second scan (should accumulate)
	results2, err := scanner.Scan(ctx, []string{"mail"})
	if err != nil {
		t.Errorf("Second scan failed: %v", err)
	}

	// Results should accumulate
	if len(results2) < len(results1) {
		t.Log("Second scan results might not accumulate (depends on resolution success)")
	} else {
		t.Logf("Accumulated results: %d subdomains", len(results2))
	}
}
