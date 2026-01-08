// Package scoring provides confidence scoring for passive reconnaissance results
package scoring

import (
	"net"
	"strings"
	"time"

	"github.com/jhaxce/origindive/v3/pkg/core"
)

// Scorer calculates confidence scores for passive IPs
type Scorer struct {
	domain string
	config *ScoringConfig
}

// ScoringConfig holds scoring configuration
type ScoringConfig struct {
	// Source weights (how much to trust each source)
	SourceWeights map[string]float64

	// Recency thresholds (in days)
	RecentThreshold   int // < X days = recent (default: 30)
	ModerateThreshold int // < X days = moderate (default: 180)
	StaleThreshold    int // > X days = stale (default: 365)

	// Scoring weights
	MultiSourceBonus float64 // Bonus per additional source (default: 0.25, max 0.50)
	RecentBonus      float64 // Bonus for recent sightings (default: 0.10)
	ModerateBonus    float64 // Bonus for moderate recency (default: 0.05)
	ReverseDNSBonus  float64 // Bonus for matching reverse DNS (default: 0.15)
	ASNMatchBonus    float64 // Bonus for matching ASN (default: 0.10)
	WHOISMatchBonus  float64 // Bonus for matching WHOIS (default: 0.10)
	GeoMatchBonus    float64 // Bonus for geo proximity (default: 0.05)

	// Penalties
	SingleSourcePenalty float64 // Penalty for only one source (default: -0.10)
	StalePenalty        float64 // Penalty for stale records (default: -0.05)
	HostingPenalty      float64 // Penalty for generic hosting (default: -0.15)

	// Base score
	BaseScore float64 // Starting score for all IPs (default: 0.3)

	// Minimum confidence threshold
	MinConfidence float64 // Filter out IPs below this (default: 0.0)
}

// DefaultScoringConfig returns default scoring configuration
func DefaultScoringConfig() *ScoringConfig {
	return &ScoringConfig{
		SourceWeights: map[string]float64{
			"securitytrails": 1.0, // Most reliable (historical DNS)
			"shodan":         0.9, // Very reliable (active scanning)
			"censys":         0.9, // Very reliable (active scanning)
			"virustotal":     0.8, // Reliable (aggregated data)
			"ct":             0.7, // Good (certificate logs)
			"wayback":        0.6, // Moderate (archived content)
			"viewdns":        0.6, // Moderate (reverse IP lookup)
			"dnsdumpster":    0.5, // Moderate (public DNS)
			"dns":            0.8, // Reliable (current DNS)
			"subdomain":      0.4, // Lower (derived from other sources)
		},
		RecentThreshold:     30,
		ModerateThreshold:   180,
		StaleThreshold:      365,
		MultiSourceBonus:    0.25,
		RecentBonus:         0.10,
		ModerateBonus:       0.05,
		ReverseDNSBonus:     0.15,
		ASNMatchBonus:       0.10,
		WHOISMatchBonus:     0.10,
		GeoMatchBonus:       0.05,
		SingleSourcePenalty: -0.10,
		StalePenalty:        -0.05,
		HostingPenalty:      -0.15,
		BaseScore:           0.3,
		MinConfidence:       0.0,
	}
}

// NewScorer creates a new confidence scorer
func NewScorer(domain string, config *ScoringConfig) *Scorer {
	if config == nil {
		config = DefaultScoringConfig()
	}
	return &Scorer{
		domain: domain,
		config: config,
	}
}

// ScoreIP calculates confidence score for a single IP
func (s *Scorer) ScoreIP(ip *core.PassiveIP, allIPs []core.PassiveIP) float64 {
	score := s.config.BaseScore

	// Factor 1: Source weight
	sourceWeight := s.getSourceWeight(ip.Source)
	score += sourceWeight * 0.2 // Scale source weight to reasonable range

	// Factor 2: Multiple sources (aggregation bonus)
	sourceCount := s.countSources(ip.IP, allIPs)
	if sourceCount > 1 {
		// Bonus increases with more sources, but caps at 2 additional sources
		bonusSources := min(sourceCount-1, 2)
		score += float64(bonusSources) * s.config.MultiSourceBonus
	} else {
		// Penalty for single source
		score += s.config.SingleSourcePenalty
	}

	// Factor 3: Recency (how fresh is the data)
	recencyScore := s.calculateRecency(ip.LastSeen)
	score += recencyScore

	// Factor 4: Reverse DNS match
	if s.hasReverseDNSMatch(ip) {
		score += s.config.ReverseDNSBonus
	}

	// Factor 5: ASN match (if available in metadata)
	if s.hasASNMatch(ip) {
		score += s.config.ASNMatchBonus
	}

	// Factor 6: WHOIS match (if available in metadata)
	if s.hasWHOISMatch(ip) {
		score += s.config.WHOISMatchBonus
	}

	// Factor 7: Geographic proximity (if available)
	if s.hasGeoMatch(ip) {
		score += s.config.GeoMatchBonus
	}

	// Factor 8: Hosting provider penalty (generic shared hosting)
	if s.isGenericHosting(ip) {
		score += s.config.HostingPenalty
	}

	// Clamp score to [0.0, 1.0]
	return clamp(score, 0.0, 1.0)
}

// ScoreAll calculates confidence scores for all passive IPs
func (s *Scorer) ScoreAll(ips []core.PassiveIP) []core.PassiveIP {
	scored := make([]core.PassiveIP, 0, len(ips))

	for _, ip := range ips {
		score := s.ScoreIP(&ip, ips)
		ip.Confidence = score

		// Filter by minimum confidence
		if score >= s.config.MinConfidence {
			scored = append(scored, ip)
		}
	}

	return scored
}

// getSourceWeight returns the weight for a given source
func (s *Scorer) getSourceWeight(source string) float64 {
	if weight, ok := s.config.SourceWeights[source]; ok {
		return weight
	}
	return 0.5 // Default weight for unknown sources
}

// countSources counts how many different sources reported the same IP
func (s *Scorer) countSources(ip string, allIPs []core.PassiveIP) int {
	sources := make(map[string]bool)
	for _, passiveIP := range allIPs {
		if passiveIP.IP == ip {
			sources[passiveIP.Source] = true
		}
	}
	return len(sources)
}

// calculateRecency returns a score based on how recent the sighting is
func (s *Scorer) calculateRecency(lastSeen time.Time) float64 {
	if lastSeen.IsZero() {
		// No timestamp available
		return 0.0
	}

	daysSince := int(time.Since(lastSeen).Hours() / 24)

	if daysSince < s.config.RecentThreshold {
		// Recent sighting (< 30 days)
		return s.config.RecentBonus
	} else if daysSince < s.config.ModerateThreshold {
		// Moderate recency (< 180 days)
		return s.config.ModerateBonus
	} else if daysSince > s.config.StaleThreshold {
		// Stale data (> 1 year)
		return s.config.StalePenalty
	}

	return 0.0 // Between moderate and stale
}

// hasReverseDNSMatch checks if reverse DNS matches the domain
func (s *Scorer) hasReverseDNSMatch(ip *core.PassiveIP) bool {
	if ip.Metadata == nil {
		return false
	}

	// Check for reverse_dns in metadata
	if reverseDNS, ok := ip.Metadata["reverse_dns"].(string); ok {
		return strings.Contains(strings.ToLower(reverseDNS), strings.ToLower(s.domain))
	}

	// Check for ptr_record in metadata
	if ptrRecord, ok := ip.Metadata["ptr_record"].(string); ok {
		return strings.Contains(strings.ToLower(ptrRecord), strings.ToLower(s.domain))
	}

	// Try actual reverse DNS lookup
	reverseDNS := s.performReverseDNS(ip.IP)
	if reverseDNS != "" {
		// Cache result in metadata
		if ip.Metadata == nil {
			ip.Metadata = make(map[string]interface{})
		}
		ip.Metadata["reverse_dns"] = reverseDNS
		return strings.Contains(strings.ToLower(reverseDNS), strings.ToLower(s.domain))
	}

	return false
}

// performReverseDNS performs actual reverse DNS lookup
func (s *Scorer) performReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// hasASNMatch checks if ASN matches expected ASN
func (s *Scorer) hasASNMatch(ip *core.PassiveIP) bool {
	if ip.Metadata == nil {
		return false
	}

	// Check for asn in metadata
	if asn, ok := ip.Metadata["asn"].(string); ok {
		asnLower := strings.ToLower(asn)

		// Exclude CDN/Cloud ASNs (these are NOT origin servers)
		cdnASNs := []string{"cloudflare", "amazon", "fastly", "akamai", "cloudfront"}
		for _, cdn := range cdnASNs {
			if strings.Contains(asnLower, cdn) {
				return false
			}
		}

		// Also check specific known CDN ASN numbers
		cdnASNNumbers := []string{"as13335", "as16509", "as14618", "as20940", "as54113"}
		for _, cdnNum := range cdnASNNumbers {
			if strings.Contains(asnLower, cdnNum) {
				return false
			}
		}

		// If ASN is present and not a CDN, it indicates ownership data
		return asn != ""
	}

	return false
}

// hasWHOISMatch checks if WHOIS data matches domain
func (s *Scorer) hasWHOISMatch(ip *core.PassiveIP) bool {
	if ip.Metadata == nil {
		return false
	}

	// Check for whois_org in metadata
	if whoisOrg, ok := ip.Metadata["whois_org"].(string); ok {
		// Simple heuristic: organization name contains domain parts
		domainParts := strings.Split(s.domain, ".")
		if len(domainParts) > 0 {
			mainDomain := domainParts[0]
			return strings.Contains(strings.ToLower(whoisOrg), strings.ToLower(mainDomain))
		}
	}

	return false
}

// hasGeoMatch checks if geographic location matches expected location
func (s *Scorer) hasGeoMatch(ip *core.PassiveIP) bool {
	if ip.Metadata == nil {
		return false
	}

	// Check for country_code in metadata
	if countryCode, ok := ip.Metadata["country_code"].(string); ok {
		// Would need expected country from domain WHOIS or config
		// For now, just check if geo data is available (indicates more detail)
		return countryCode != "" && countryCode != "UNKNOWN"
	}

	return false
}

// isGenericHosting checks if IP belongs to generic hosting provider
func (s *Scorer) isGenericHosting(ip *core.PassiveIP) bool {
	if ip.Metadata == nil {
		return false
	}

	// Check for hosting_provider in metadata
	if provider, ok := ip.Metadata["hosting_provider"].(string); ok {
		provider = strings.ToLower(provider)

		// Common generic hosting providers (shared hosting red flags)
		genericProviders := []string{
			"digitalocean", "linode", "vultr", "ovh",
			"hetzner", "contabo", "namecheap", "godaddy",
			"hostgator", "bluehost", "hostinger", "siteground",
		}

		for _, generic := range genericProviders {
			if strings.Contains(provider, generic) {
				return true
			}
		}
	}

	// Check organization field
	if org, ok := ip.Metadata["organization"].(string); ok {
		org = strings.ToLower(org)
		if strings.Contains(org, "hosting") || strings.Contains(org, "datacenter") {
			return true
		}
	}

	return false
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
