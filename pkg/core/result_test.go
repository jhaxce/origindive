package core

import (
	"testing"
	"time"
)

func TestNewScanResult(t *testing.T) {
	domain := "example.com"
	mode := ModeActive

	result := NewScanResult(domain, mode)

	if result.Domain != domain {
		t.Errorf("Domain = %s, want %s", result.Domain, domain)
	}
	if result.Mode != mode {
		t.Errorf("Mode = %s, want %s", result.Mode, mode)
	}
	if result.Success == nil {
		t.Error("Success slice is nil")
	}
	if result.Redirects == nil {
		t.Error("Redirects slice is nil")
	}
	if result.Other == nil {
		t.Error("Other slice is nil")
	}
	if result.Timeouts == nil {
		t.Error("Timeouts slice is nil")
	}
	if result.Errors == nil {
		t.Error("Errors slice is nil")
	}
	if result.Summary.WAFStats == nil {
		t.Error("WAFStats map is nil")
	}
}

func TestAddResult(t *testing.T) {
	sr := NewScanResult("example.com", ModeActive)

	tests := []struct {
		name     string
		result   *IPResult
		checkLen func(*ScanResult) int
	}{
		{
			"200 OK",
			&IPResult{IP: "192.0.2.1", Status: "200", HTTPCode: 200},
			func(s *ScanResult) int { return len(s.Success) },
		},
		{
			"3xx Redirect",
			&IPResult{IP: "192.0.2.2", Status: "3xx", HTTPCode: 301},
			func(s *ScanResult) int { return len(s.Redirects) },
		},
		{
			"Timeout",
			&IPResult{IP: "192.0.2.3", Status: "timeout"},
			func(s *ScanResult) int { return len(s.Timeouts) },
		},
		{
			"Error",
			&IPResult{IP: "192.0.2.4", Status: "error", Error: "connection refused"},
			func(s *ScanResult) int { return len(s.Errors) },
		},
		{
			"Other (4xx)",
			&IPResult{IP: "192.0.2.5", Status: "4xx", HTTPCode: 404},
			func(s *ScanResult) int { return len(s.Other) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.checkLen(sr)
			sr.AddResult(tt.result)
			after := tt.checkLen(sr)
			if after != before+1 {
				t.Errorf("Result not added correctly: before=%d, after=%d", before, after)
			}
		})
	}
}

func TestFinalize(t *testing.T) {
	sr := NewScanResult("example.com", ModeActive)
	sr.StartTime = time.Now().Add(-5 * time.Second)
	sr.EndTime = time.Now()

	sr.Finalize()

	if sr.Summary.Duration == 0 {
		t.Error("Duration is zero after Finalize")
	}
	if sr.Summary.Duration < 4*time.Second || sr.Summary.Duration > 6*time.Second {
		t.Errorf("Duration = %v, expected ~5s", sr.Summary.Duration)
	}
}

func TestGetSummary(t *testing.T) {
	sr := NewScanResult("example.com", ModeActive)
	sr.Summary.TotalIPs = 100
	sr.Summary.ScannedIPs = 95
	sr.Summary.SkippedIPs = 5
	sr.Summary.SuccessCount = 10

	summary := sr.GetSummary()
	if summary.TotalIPs != 100 {
		t.Errorf("TotalIPs = %d, want 100", summary.TotalIPs)
	}
	if summary.ScannedIPs != 95 {
		t.Errorf("ScannedIPs = %d, want 95", summary.ScannedIPs)
	}
	if summary.SkippedIPs != 5 {
		t.Errorf("SkippedIPs = %d, want 5", summary.SkippedIPs)
	}
	if summary.SuccessCount != 10 {
		t.Errorf("SuccessCount = %d, want 10", summary.SuccessCount)
	}
}

func TestIPResult(t *testing.T) {
	result := &IPResult{
		IP:           "192.0.2.1",
		Status:       "200",
		HTTPCode:     200,
		ResponseTime: "123ms",
		BodyHash:     "abc123def456",
		Title:        "Example Title",
		ContentType:  "text/html",
		Server:       "nginx/1.18.0",
	}

	if result.IP != "192.0.2.1" {
		t.Errorf("IP = %s, want 192.0.2.1", result.IP)
	}
	if result.Status != "200" {
		t.Errorf("Status = %s, want 200", result.Status)
	}
	if result.HTTPCode != 200 {
		t.Errorf("HTTPCode = %d, want 200", result.HTTPCode)
	}
	if result.BodyHash != "abc123def456" {
		t.Errorf("BodyHash = %s, want abc123def456", result.BodyHash)
	}
	if result.Title != "Example Title" {
		t.Errorf("Title = %s, want Example Title", result.Title)
	}
}

func TestPassiveIP(t *testing.T) {
	now := time.Now()
	passiveIP := PassiveIP{
		IP:         "192.0.2.1",
		Source:     "ct",
		Confidence: 0.8,
		FirstSeen:  now.Add(-24 * time.Hour),
		LastSeen:   now,
		Metadata: map[string]interface{}{
			"subdomain": "www.example.com",
		},
	}

	if passiveIP.IP != "192.0.2.1" {
		t.Errorf("IP = %s, want 192.0.2.1", passiveIP.IP)
	}
	if passiveIP.Source != "ct" {
		t.Errorf("Source = %s, want ct", passiveIP.Source)
	}
	if passiveIP.Confidence != 0.8 {
		t.Errorf("Confidence = %f, want 0.8", passiveIP.Confidence)
	}
	if passiveIP.Metadata["subdomain"] != "www.example.com" {
		t.Errorf("Metadata subdomain = %v, want www.example.com", passiveIP.Metadata["subdomain"])
	}
}

func TestScanMode(t *testing.T) {
	if ModePassive != "passive" {
		t.Errorf("ModePassive = %s, want passive", ModePassive)
	}
	if ModeActive != "active" {
		t.Errorf("ModeActive = %s, want active", ModeActive)
	}
	if ModeAuto != "auto" {
		t.Errorf("ModeAuto = %s, want auto", ModeAuto)
	}
}
