// Package scoring - Confidence scoring tests
package scoring

import (
	"testing"
	"time"

	"github.com/jhaxce/origindive/pkg/core"
)

// Test default configuration
func TestDefaultScoringConfig(t *testing.T) {
	config := DefaultScoringConfig()

	if config.BaseScore != 0.3 {
		t.Errorf("Expected BaseScore 0.3, got %f", config.BaseScore)
	}

	if config.MultiSourceBonus != 0.25 {
		t.Errorf("Expected MultiSourceBonus 0.25, got %f", config.MultiSourceBonus)
	}

	if config.RecentThreshold != 30 {
		t.Errorf("Expected RecentThreshold 30, got %d", config.RecentThreshold)
	}

	// Check source weights
	if config.SourceWeights["securitytrails"] != 1.0 {
		t.Errorf("Expected SecurityTrails weight 1.0, got %f", config.SourceWeights["securitytrails"])
	}

	if config.SourceWeights["shodan"] != 0.9 {
		t.Errorf("Expected Shodan weight 0.9, got %f", config.SourceWeights["shodan"])
	}
}

// Test NewScorer creation
func TestNewScorer(t *testing.T) {
	scorer := NewScorer("example.com", nil)

	if scorer.domain != "example.com" {
		t.Errorf("Expected domain example.com, got %s", scorer.domain)
	}

	if scorer.config == nil {
		t.Error("Expected config to be initialized")
	}

	// Test with custom config
	customConfig := &ScoringConfig{BaseScore: 0.5}
	scorer2 := NewScorer("test.com", customConfig)

	if scorer2.config.BaseScore != 0.5 {
		t.Errorf("Expected custom BaseScore 0.5, got %f", scorer2.config.BaseScore)
	}
}

// Test single source scoring
func TestScoreIP_SingleSource(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	ip := core.PassiveIP{
		IP:         "192.0.2.1",
		Source:     "shodan",
		Confidence: 0.0,
		LastSeen:   time.Now(),
	}

	allIPs := []core.PassiveIP{ip}

	score := scorer.ScoreIP(&ip, allIPs)

	// Base (0.3) + Shodan weight (0.9 * 0.2 = 0.18) + Recent (0.10) + SingleSourcePenalty (-0.10)
	// = 0.3 + 0.18 + 0.10 - 0.10 = 0.48
	expectedMin := 0.45
	expectedMax := 0.55

	if score < expectedMin || score > expectedMax {
		t.Errorf("Single source score out of range: got %f, expected ~0.48", score)
	}
}

// Test multiple sources scoring
func TestScoreIP_MultipleSources(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	now := time.Now()

	allIPs := []core.PassiveIP{
		{IP: "192.0.2.1", Source: "shodan", LastSeen: now},
		{IP: "192.0.2.1", Source: "censys", LastSeen: now},
		{IP: "192.0.2.1", Source: "securitytrails", LastSeen: now},
	}

	score := scorer.ScoreIP(&allIPs[0], allIPs)

	// Should have multi-source bonus (2 additional sources = 0.50)
	// No single source penalty
	if score < 0.7 {
		t.Errorf("Multi-source score too low: got %f, expected > 0.7", score)
	}
}

// Test recency scoring - recent
func TestRecency_Recent(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	recent := time.Now().Add(-10 * 24 * time.Hour) // 10 days ago
	score := scorer.calculateRecency(recent)

	if score != scorer.config.RecentBonus {
		t.Errorf("Recent score incorrect: got %f, expected %f", score, scorer.config.RecentBonus)
	}
}

// Test recency scoring - moderate
func TestRecency_Moderate(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	moderate := time.Now().Add(-100 * 24 * time.Hour) // 100 days ago
	score := scorer.calculateRecency(moderate)

	if score != scorer.config.ModerateBonus {
		t.Errorf("Moderate score incorrect: got %f, expected %f", score, scorer.config.ModerateBonus)
	}
}

// Test recency scoring - stale
func TestRecency_Stale(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	stale := time.Now().Add(-400 * 24 * time.Hour) // 400 days ago
	score := scorer.calculateRecency(stale)

	if score != scorer.config.StalePenalty {
		t.Errorf("Stale score incorrect: got %f, expected %f", score, scorer.config.StalePenalty)
	}
}

// Test recency scoring - zero time
func TestRecency_ZeroTime(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	score := scorer.calculateRecency(time.Time{})

	if score != 0.0 {
		t.Errorf("Zero time score incorrect: got %f, expected 0.0", score)
	}
}

// Test source counting
func TestCountSources(t *testing.T) {
	scorer := NewScorer("example.com", nil)

	allIPs := []core.PassiveIP{
		{IP: "192.0.2.1", Source: "shodan"},
		{IP: "192.0.2.1", Source: "censys"},
		{IP: "192.0.2.1", Source: "shodan"}, // Duplicate source
		{IP: "192.0.2.2", Source: "virustotal"},
	}

	count := scorer.countSources("192.0.2.1", allIPs)

	if count != 2 {
		t.Errorf("Source count incorrect: got %d, expected 2 (shodan + censys)", count)
	}
}

// Test reverse DNS match
func TestHasReverseDNSMatch(t *testing.T) {
	scorer := NewScorer("example.com", nil)

	// Test with metadata reverse_dns
	ip1 := core.PassiveIP{
		IP: "192.0.2.1",
		Metadata: map[string]interface{}{
			"reverse_dns": "server.example.com",
		},
	}

	if !scorer.hasReverseDNSMatch(&ip1) {
		t.Error("Expected reverse DNS match for server.example.com")
	}

	// Test with ptr_record
	ip2 := core.PassiveIP{
		IP: "192.0.2.2",
		Metadata: map[string]interface{}{
			"ptr_record": "web.example.com",
		},
	}

	if !scorer.hasReverseDNSMatch(&ip2) {
		t.Error("Expected reverse DNS match for web.example.com")
	}

	// Test without match
	ip3 := core.PassiveIP{
		IP: "192.0.2.3",
		Metadata: map[string]interface{}{
			"reverse_dns": "unrelated.com",
		},
	}

	if scorer.hasReverseDNSMatch(&ip3) {
		t.Error("Expected no reverse DNS match for unrelated.com")
	}
}

// Test ASN match
func TestHasASNMatch(t *testing.T) {
	scorer := NewScorer("example.com", nil)

	// Test with valid ASN (not CDN)
	ip1 := core.PassiveIP{
		IP: "192.0.2.1",
		Metadata: map[string]interface{}{
			"asn": "AS13335",
		},
	}

	// This should NOT match because AS13335 is Cloudflare
	if scorer.hasASNMatch(&ip1) {
		t.Error("Expected no ASN match for Cloudflare ASN")
	}

	// Test with non-CDN ASN
	ip2 := core.PassiveIP{
		IP: "192.0.2.2",
		Metadata: map[string]interface{}{
			"asn": "AS4775",
		},
	}

	if !scorer.hasASNMatch(&ip2) {
		t.Error("Expected ASN match for AS4775")
	}
}

// Test WHOIS match
func TestHasWHOISMatch(t *testing.T) {
	scorer := NewScorer("example.com", nil)

	// Test with matching organization
	ip1 := core.PassiveIP{
		IP: "192.0.2.1",
		Metadata: map[string]interface{}{
			"whois_org": "Example Corporation",
		},
	}

	if !scorer.hasWHOISMatch(&ip1) {
		t.Error("Expected WHOIS match for Example Corporation")
	}

	// Test without match
	ip2 := core.PassiveIP{
		IP: "192.0.2.2",
		Metadata: map[string]interface{}{
			"whois_org": "Unrelated Company",
		},
	}

	if scorer.hasWHOISMatch(&ip2) {
		t.Error("Expected no WHOIS match for Unrelated Company")
	}
}

// Test geographic match
func TestHasGeoMatch(t *testing.T) {
	scorer := NewScorer("example.com", nil)

	// Test with valid country code
	ip1 := core.PassiveIP{
		IP: "192.0.2.1",
		Metadata: map[string]interface{}{
			"country_code": "US",
		},
	}

	if !scorer.hasGeoMatch(&ip1) {
		t.Error("Expected geo match for valid country code")
	}

	// Test with unknown country
	ip2 := core.PassiveIP{
		IP: "192.0.2.2",
		Metadata: map[string]interface{}{
			"country_code": "UNKNOWN",
		},
	}

	if scorer.hasGeoMatch(&ip2) {
		t.Error("Expected no geo match for UNKNOWN country")
	}
}

// Test generic hosting detection
func TestIsGenericHosting(t *testing.T) {
	scorer := NewScorer("example.com", nil)

	// Test DigitalOcean
	ip1 := core.PassiveIP{
		IP: "192.0.2.1",
		Metadata: map[string]interface{}{
			"hosting_provider": "DigitalOcean LLC",
		},
	}

	if !scorer.isGenericHosting(&ip1) {
		t.Error("Expected DigitalOcean to be detected as generic hosting")
	}

	// Test organization with "hosting"
	ip2 := core.PassiveIP{
		IP: "192.0.2.2",
		Metadata: map[string]interface{}{
			"organization": "Generic Hosting Services",
		},
	}

	if !scorer.isGenericHosting(&ip2) {
		t.Error("Expected organization with 'hosting' to be detected")
	}

	// Test non-generic provider
	ip3 := core.PassiveIP{
		IP: "192.0.2.3",
		Metadata: map[string]interface{}{
			"hosting_provider": "Example Corporation",
		},
	}

	if scorer.isGenericHosting(&ip3) {
		t.Error("Expected Example Corporation not to be generic hosting")
	}
}

// Test source weight retrieval
func TestGetSourceWeight(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	// Test known source
	weight := scorer.getSourceWeight("shodan")
	if weight != 0.9 {
		t.Errorf("Expected Shodan weight 0.9, got %f", weight)
	}

	// Test unknown source
	weight = scorer.getSourceWeight("unknown_source")
	if weight != 0.5 {
		t.Errorf("Expected default weight 0.5 for unknown source, got %f", weight)
	}
}

// Test ScoreAll function
func TestScoreAll(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	now := time.Now()

	ips := []core.PassiveIP{
		{IP: "192.0.2.1", Source: "shodan", LastSeen: now},
		{IP: "192.0.2.1", Source: "censys", LastSeen: now},
		{IP: "192.0.2.2", Source: "virustotal", LastSeen: now.Add(-200 * 24 * time.Hour)},
	}

	scored := scorer.ScoreAll(ips)

	if len(scored) != 3 {
		t.Errorf("Expected 3 scored IPs, got %d", len(scored))
	}

	// First IP should have higher score (multiple sources + recent)
	if scored[0].Confidence <= 0.0 {
		t.Error("Expected positive confidence score")
	}

	if scored[0].Confidence > 1.0 {
		t.Error("Expected confidence score <= 1.0")
	}
}

// Test ScoreAll with minimum confidence filter
func TestScoreAll_MinConfidence(t *testing.T) {
	config := DefaultScoringConfig()
	config.MinConfidence = 0.6 // High threshold

	scorer := NewScorer("example.com", config)

	now := time.Now()

	ips := []core.PassiveIP{
		// High confidence (multiple sources + recent)
		{IP: "192.0.2.1", Source: "shodan", LastSeen: now},
		{IP: "192.0.2.1", Source: "censys", LastSeen: now},
		{IP: "192.0.2.1", Source: "securitytrails", LastSeen: now},

		// Low confidence (single source + stale)
		{IP: "192.0.2.2", Source: "ct", LastSeen: now.Add(-400 * 24 * time.Hour)},
	}

	scored := scorer.ScoreAll(ips)

	// Should filter out low confidence IPs
	if len(scored) < 3 {
		t.Logf("Filtered results: %d IPs (expected 3 for high-confidence IP)", len(scored))
	}

	// All scored IPs should meet minimum threshold
	for _, ip := range scored {
		if ip.Confidence < config.MinConfidence {
			t.Errorf("IP %s has confidence %f below threshold %f", ip.IP, ip.Confidence, config.MinConfidence)
		}
	}
}

// Test score clamping
func TestClamp(t *testing.T) {
	tests := []struct {
		value    float64
		min      float64
		max      float64
		expected float64
	}{
		{0.5, 0.0, 1.0, 0.5},  // Within range
		{1.5, 0.0, 1.0, 1.0},  // Above max
		{-0.5, 0.0, 1.0, 0.0}, // Below min
		{0.0, 0.0, 1.0, 0.0},  // At min
		{1.0, 0.0, 1.0, 1.0},  // At max
	}

	for _, test := range tests {
		result := clamp(test.value, test.min, test.max)
		if result != test.expected {
			t.Errorf("clamp(%f, %f, %f) = %f, expected %f",
				test.value, test.min, test.max, result, test.expected)
		}
	}
}

// Test comprehensive scoring scenario
func TestComprehensiveScoring(t *testing.T) {
	scorer := NewScorer("example.com", DefaultScoringConfig())

	now := time.Now()

	// Perfect score scenario: multiple sources, recent, reverse DNS, ASN, WHOIS, geo
	perfectIP := core.PassiveIP{
		IP:       "192.0.2.1",
		Source:   "securitytrails",
		LastSeen: now,
		Metadata: map[string]interface{}{
			"reverse_dns":  "origin.example.com",
			"asn":          "AS12345",
			"whois_org":    "Example Corporation",
			"country_code": "US",
		},
	}

	allIPs := []core.PassiveIP{
		perfectIP,
		{IP: "192.0.2.1", Source: "shodan", LastSeen: now},
		{IP: "192.0.2.1", Source: "censys", LastSeen: now},
	}

	score := scorer.ScoreIP(&perfectIP, allIPs)

	// Should be very high score (close to 1.0)
	if score < 0.8 {
		t.Errorf("Perfect scenario score too low: got %f, expected > 0.8", score)
	}

	t.Logf("Perfect scenario score: %f", score)

	// Worst score scenario: single source, stale, generic hosting
	worstIP := core.PassiveIP{
		IP:       "192.0.2.99",
		Source:   "ct",
		LastSeen: now.Add(-400 * 24 * time.Hour),
		Metadata: map[string]interface{}{
			"hosting_provider": "DigitalOcean",
		},
	}

	worstAllIPs := []core.PassiveIP{worstIP}

	worstScore := scorer.ScoreIP(&worstIP, worstAllIPs)

	// Should be low score
	if worstScore > 0.5 {
		t.Errorf("Worst scenario score too high: got %f, expected < 0.5", worstScore)
	}

	t.Logf("Worst scenario score: %f", worstScore)
}
