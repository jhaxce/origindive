// Package api provides API client validation and failover for passive sources
package api

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Source represents a passive reconnaissance source
type Source string

const (
	SourceShodan         Source = "shodan"
	SourceCensys         Source = "censys"
	SourceSecurityTrails Source = "securitytrails"
	SourceVirusTotal     Source = "virustotal"
	SourceZoomEye        Source = "zoomeye"
	SourceCT             Source = "ct"
	SourceViewDNS        Source = "viewdns"
	SourceDNSDumpster    Source = "dnsdumpster"
	SourceWayback        Source = "wayback"
	SourceDNS            Source = "dns"
)

// Status represents the current status of an API
type Status string

const (
	StatusAvailable   Status = "available"    // API is working
	StatusRateLimited Status = "rate_limited" // Hit rate limit
	StatusError       Status = "error"        // API error
	StatusUnchecked   Status = "unchecked"    // Not yet validated
	StatusDisabled    Status = "disabled"     // Manually disabled
)

// APIStatus tracks the status of a passive source API
type APIStatus struct {
	Source       Source
	Status       Status
	LastChecked  time.Time
	LastError    error
	RateLimitEnd time.Time // When rate limit expires
	RequestsMade int       // Total requests made
	mu           sync.RWMutex
}

// Manager manages API clients and handles failover
type Manager struct {
	sources  map[Source]*APIStatus
	failover bool // Enable automatic failover

	// Multiple API keys per source for rotation
	shodanKeys   []string
	censysCreds  []CensysCredential
	currentIndex map[Source]int // Current key index for each source
	mu           sync.RWMutex
}

// CensysCredential holds Censys API credentials
type CensysCredential struct {
	ID     string
	Secret string
}

// NewManager creates a new API manager
func NewManager(failoverEnabled bool) *Manager {
	return &Manager{
		sources:      make(map[Source]*APIStatus),
		failover:     failoverEnabled,
		currentIndex: make(map[Source]int),
	}
}

// SetShodanKeys sets multiple Shodan API keys for rotation
func (m *Manager) SetShodanKeys(keys []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shodanKeys = keys
	m.currentIndex[SourceShodan] = 0
}

// SetCensysCreds sets multiple Censys credentials for rotation
func (m *Manager) SetCensysCreds(creds []CensysCredential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.censysCreds = creds
	m.currentIndex[SourceCensys] = 0
}

// GetCurrentKey returns the current API key for a source
func (m *Manager) GetCurrentKey(source Source) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	idx := m.currentIndex[source]

	switch source {
	case SourceShodan:
		if len(m.shodanKeys) == 0 {
			return nil, fmt.Errorf("no Shodan keys configured")
		}
		if idx >= len(m.shodanKeys) {
			return nil, fmt.Errorf("all Shodan keys exhausted")
		}
		return m.shodanKeys[idx], nil

	case SourceCensys:
		if len(m.censysCreds) == 0 {
			return nil, fmt.Errorf("no Censys credentials configured")
		}
		if idx >= len(m.censysCreds) {
			return nil, fmt.Errorf("all Censys credentials exhausted")
		}
		return m.censysCreds[idx], nil

	default:
		return nil, nil // CT and DNS don't need keys
	}
}

// RotateKey rotates to the next API key for a source
func (m *Manager) RotateKey(source Source) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := m.currentIndex[source]

	switch source {
	case SourceShodan:
		if idx+1 < len(m.shodanKeys) {
			m.currentIndex[source] = idx + 1
			return true
		}

	case SourceCensys:
		if idx+1 < len(m.censysCreds) {
			m.currentIndex[source] = idx + 1
			return true
		}
	}

	return false // No more keys available
}

// ResetKeyRotation resets key rotation for a source (use after cooldown)
func (m *Manager) ResetKeyRotation(source Source) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentIndex[source] = 0
}

// RegisterSource registers a new API source
func (m *Manager) RegisterSource(source Source) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sources[source]; !exists {
		m.sources[source] = &APIStatus{
			Source:      source,
			Status:      StatusUnchecked,
			LastChecked: time.Now(),
		}
	}
}

// ValidateSource checks if an API source is configured and working
func (m *Manager) ValidateSource(ctx context.Context, source Source, validator func(context.Context) error) error {
	m.mu.RLock()
	status, exists := m.sources[source]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("source %s not registered", source)
	}

	status.mu.Lock()
	defer status.mu.Unlock()

	// Check if we're still in rate limit cooldown
	if status.Status == StatusRateLimited && time.Now().Before(status.RateLimitEnd) {
		return fmt.Errorf("source %s is rate limited until %s", source, status.RateLimitEnd.Format(time.RFC3339))
	}

	// Run validator
	err := validator(ctx)
	status.LastChecked = time.Now()

	if err != nil {
		status.LastError = err
		// Check if this is a rate limit error
		if isRateLimitError(err) {
			status.Status = StatusRateLimited
			// Set cooldown period (default 1 hour)
			status.RateLimitEnd = time.Now().Add(1 * time.Hour)
		} else {
			status.Status = StatusError
		}
		return err
	}

	status.Status = StatusAvailable
	status.LastError = nil
	return nil
}

// GetStatus returns the current status of a source
func (m *Manager) GetStatus(source Source) (*APIStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status, exists := m.sources[source]
	if !exists {
		return nil, fmt.Errorf("source %s not registered", source)
	}

	status.mu.RLock()
	defer status.mu.RUnlock()

	// Return a copy to avoid race conditions
	return &APIStatus{
		Source:       status.Source,
		Status:       status.Status,
		LastChecked:  status.LastChecked,
		LastError:    status.LastError,
		RateLimitEnd: status.RateLimitEnd,
		RequestsMade: status.RequestsMade,
	}, nil
}

// GetAvailableSources returns a list of sources that are currently available
func (m *Manager) GetAvailableSources() []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var available []Source
	for source, status := range m.sources {
		status.mu.RLock()
		// Include sources that are available or unchecked
		if status.Status == StatusAvailable || status.Status == StatusUnchecked {
			available = append(available, source)
		}
		// Also include rate-limited sources if cooldown expired
		if status.Status == StatusRateLimited && time.Now().After(status.RateLimitEnd) {
			available = append(available, source)
		}
		status.mu.RUnlock()
	}
	return available
}

// MarkRateLimited marks a source as rate limited and tries to rotate key
// Returns true if rotated to next key, false if all keys exhausted
func (m *Manager) MarkRateLimited(source Source, duration time.Duration) bool {
	m.mu.RLock()
	status, exists := m.sources[source]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	// Try to rotate to next key
	rotated := m.RotateKey(source)

	if !rotated {
		// No more keys, mark as rate limited
		status.mu.Lock()
		defer status.mu.Unlock()

		status.Status = StatusRateLimited
		status.RateLimitEnd = time.Now().Add(duration)
		status.LastChecked = time.Now()
		return false
	}

	// Rotated to next key, keep status as available
	return true
}

// IncrementRequests increments the request counter for a source
func (m *Manager) IncrementRequests(source Source) {
	m.mu.RLock()
	status, exists := m.sources[source]
	m.mu.RUnlock()

	if !exists {
		return
	}

	status.mu.Lock()
	defer status.mu.Unlock()

	status.RequestsMade++
}

// GetNextAvailableSource returns the next available source for failover
// Returns empty string if no sources available
func (m *Manager) GetNextAvailableSource(currentSource Source) Source {
	if !m.failover {
		return ""
	}

	available := m.GetAvailableSources()
	if len(available) == 0 {
		return ""
	}

	// Find next source after current one
	for i, source := range available {
		if source == currentSource && i+1 < len(available) {
			return available[i+1]
		}
	}

	// If current source is last or not found, return first available
	if len(available) > 0 && available[0] != currentSource {
		return available[0]
	}

	return ""
}

// AllStatus returns status for all registered sources
func (m *Manager) AllStatus() map[Source]*APIStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[Source]*APIStatus)
	for source, status := range m.sources {
		status.mu.RLock()
		result[source] = &APIStatus{
			Source:       status.Source,
			Status:       status.Status,
			LastChecked:  status.LastChecked,
			LastError:    status.LastError,
			RateLimitEnd: status.RateLimitEnd,
			RequestsMade: status.RequestsMade,
		}
		status.mu.RUnlock()
	}
	return result
}

// isRateLimitError checks if an error is a rate limit error
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	// Common rate limit error strings
	msg := err.Error()
	return contains(msg, "rate limit") ||
		contains(msg, "429") ||
		contains(msg, "too many requests") ||
		contains(msg, "quota exceeded")
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	// Simple case-insensitive check
	s = toLower(s)
	substr = toLower(substr)
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
