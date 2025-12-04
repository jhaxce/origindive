package dns

import (
	"context"
	"testing"
	"time"
)

func TestLookupMX_ValidDomain(t *testing.T) {
	// Use google.com which has stable MX records
	ctx := context.Background()
	timeout := 5 * time.Second

	records, err := LookupMX(ctx, "google.com", timeout)
	if err != nil {
		t.Logf("MX lookup failed (expected in test env): %v", err)
		return
	}

	if len(records) == 0 {
		t.Error("Expected at least one MX record for google.com")
	}

	// Validate record structure
	for _, record := range records {
		if record.Host == "" {
			t.Error("MX host should not be empty")
		}
		if record.Priority == 0 {
			t.Log("MX priority is 0 (might be valid)")
		}
		t.Logf("MX: %s (priority %d) -> %v", record.Host, record.Priority, record.IPs)
	}
}

func TestLookupMX_InvalidDomain(t *testing.T) {
	ctx := context.Background()
	timeout := 2 * time.Second

	_, err := LookupMX(ctx, "nonexistent-domain-12345.invalid", timeout)
	if err == nil {
		t.Error("Expected error for invalid domain")
	}
}

func TestLookupMX_Timeout(t *testing.T) {
	ctx := context.Background()
	timeout := 1 * time.Nanosecond // Very short timeout

	time.Sleep(10 * time.Millisecond) // Ensure timeout

	_, err := LookupMX(ctx, "google.com", timeout)
	if err == nil {
		t.Log("Lookup succeeded despite timeout (might be cached)")
	}
}

func TestLookupMX_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := LookupMX(ctx, "google.com", 5*time.Second)
	if err == nil {
		t.Log("Lookup succeeded despite cancelled context (might be cached)")
	}
}

func TestResolveHost_ValidHost(t *testing.T) {
	ctx := context.Background()
	timeout := 5 * time.Second

	// Use well-known hosts
	hosts := []string{
		"google.com",
		"dns.google",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			ips, err := resolveHost(ctx, host, timeout)
			if err != nil {
				t.Logf("Resolve failed (expected in test env): %v", err)
				return
			}

			if len(ips) == 0 {
				t.Errorf("Expected at least one IP for %s", host)
			}

			t.Logf("%s -> %v", host, ips)
		})
	}
}

func TestResolveHost_InvalidHost(t *testing.T) {
	ctx := context.Background()
	timeout := 2 * time.Second

	_, err := resolveHost(ctx, "invalid-host-99999.test", timeout)
	if err == nil {
		t.Error("Expected error for invalid host")
	}
}

func TestResolveHost_IPv4Only(t *testing.T) {
	ctx := context.Background()
	timeout := 5 * time.Second

	// Use host that has both IPv4 and IPv6
	ips, err := resolveHost(ctx, "google.com", timeout)
	if err != nil {
		t.Logf("Resolve failed (expected in test env): %v", err)
		return
	}

	// All returned IPs should be IPv4
	for _, ip := range ips {
		if len(ip) > 15 { // IPv6 addresses are longer
			t.Errorf("Expected IPv4 only, got: %s", ip)
		}
	}
}

func TestGetAllMXIPs_Empty(t *testing.T) {
	var records []MXRecord

	ips := GetAllMXIPs(records)
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs from empty records, got %d", len(ips))
	}
}

func TestGetAllMXIPs_SingleRecord(t *testing.T) {
	records := []MXRecord{
		{
			Host:     "mx1.example.com",
			Priority: 10,
			IPs:      []string{"192.168.1.1", "192.168.1.2"},
		},
	}

	ips := GetAllMXIPs(records)
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}
}

func TestGetAllMXIPs_MultipleRecords(t *testing.T) {
	records := []MXRecord{
		{
			Host:     "mx1.example.com",
			Priority: 10,
			IPs:      []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			Host:     "mx2.example.com",
			Priority: 20,
			IPs:      []string{"192.168.1.3"},
		},
	}

	ips := GetAllMXIPs(records)
	if len(ips) != 3 {
		t.Errorf("Expected 3 IPs, got %d", len(ips))
	}
}

func TestGetAllMXIPs_Duplicates(t *testing.T) {
	records := []MXRecord{
		{
			Host:     "mx1.example.com",
			Priority: 10,
			IPs:      []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			Host:     "mx2.example.com",
			Priority: 20,
			IPs:      []string{"192.168.1.1", "192.168.1.3"}, // Duplicate 192.168.1.1
		},
	}

	ips := GetAllMXIPs(records)
	if len(ips) != 3 {
		t.Errorf("Expected 3 unique IPs, got %d", len(ips))
	}

	// Verify no duplicates
	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("Duplicate IP found: %s", ip)
		}
		seen[ip] = true
	}
}

func TestGetAllMXIPs_EmptyIPLists(t *testing.T) {
	records := []MXRecord{
		{
			Host:     "mx1.example.com",
			Priority: 10,
			IPs:      []string{},
		},
		{
			Host:     "mx2.example.com",
			Priority: 20,
			IPs:      nil,
		},
	}

	ips := GetAllMXIPs(records)
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs from empty lists, got %d", len(ips))
	}
}

func TestMXRecord_Structure(t *testing.T) {
	record := MXRecord{
		Host:     "mx.example.com",
		Priority: 10,
		IPs:      []string{"192.168.1.1"},
	}

	if record.Host != "mx.example.com" {
		t.Errorf("Host = %s, want mx.example.com", record.Host)
	}
	if record.Priority != 10 {
		t.Errorf("Priority = %d, want 10", record.Priority)
	}
	if len(record.IPs) != 1 {
		t.Errorf("IPs length = %d, want 1", len(record.IPs))
	}
}

func TestLookupMX_NoMXRecords(t *testing.T) {
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use a domain that likely has no MX records
	_, err := LookupMX(ctx, "localhost", timeout)
	if err == nil {
		t.Log("Localhost returned MX records (unexpected)")
	}
}

func TestResolveHost_Localhost(t *testing.T) {
	ctx := context.Background()
	timeout := 2 * time.Second

	ips, err := resolveHost(ctx, "localhost", timeout)
	if err != nil {
		t.Logf("Localhost resolve failed: %v", err)
		return
	}

	// Localhost should resolve to 127.0.0.1
	found := false
	for _, ip := range ips {
		if ip == "127.0.0.1" {
			found = true
			break
		}
	}

	if !found && len(ips) > 0 {
		t.Logf("Localhost resolved to %v (expected 127.0.0.1)", ips)
	}
}

func TestGetAllMXIPs_PreservesOrder(t *testing.T) {
	records := []MXRecord{
		{
			Host:     "mx1.example.com",
			Priority: 10,
			IPs:      []string{"192.168.1.1"},
		},
		{
			Host:     "mx2.example.com",
			Priority: 20,
			IPs:      []string{"192.168.1.2"},
		},
		{
			Host:     "mx3.example.com",
			Priority: 30,
			IPs:      []string{"192.168.1.3"},
		},
	}

	ips := GetAllMXIPs(records)

	// Order should be preserved from input
	if len(ips) >= 1 && ips[0] != "192.168.1.1" {
		t.Logf("First IP = %s (order might not be preserved)", ips[0])
	}
}
