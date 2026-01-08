package api

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name            string
		failoverEnabled bool
	}{
		{"with failover", true},
		{"without failover", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManager(tt.failoverEnabled)
			if m == nil {
				t.Fatal("NewManager() returned nil")
			}
			if m.failover != tt.failoverEnabled {
				t.Errorf("failover = %v, want %v", m.failover, tt.failoverEnabled)
			}
			if m.sources == nil {
				t.Error("sources map should be initialized")
			}
			if m.currentIndex == nil {
				t.Error("currentIndex map should be initialized")
			}
		})
	}
}

func TestManager_SetShodanKeys(t *testing.T) {
	m := NewManager(true)
	keys := []string{"key1", "key2", "key3"}

	m.SetShodanKeys(keys)

	if len(m.shodanKeys) != 3 {
		t.Errorf("shodanKeys count = %d, want 3", len(m.shodanKeys))
	}
	if m.currentIndex[SourceShodan] != 0 {
		t.Error("currentIndex should be reset to 0")
	}
}

func TestManager_SetCensysCreds(t *testing.T) {
	m := NewManager(true)
	creds := []CensysCredential{
		{ID: "id1", Secret: "secret1"},
		{ID: "id2", Secret: "secret2"},
	}

	m.SetCensysCreds(creds)

	if len(m.censysCreds) != 2 {
		t.Errorf("censysCreds count = %d, want 2", len(m.censysCreds))
	}
	if m.currentIndex[SourceCensys] != 0 {
		t.Error("currentIndex should be reset to 0")
	}
}

func TestManager_GetCurrentKey_Shodan(t *testing.T) {
	m := NewManager(true)
	keys := []string{"key1", "key2"}
	m.SetShodanKeys(keys)

	key, err := m.GetCurrentKey(SourceShodan)
	if err != nil {
		t.Fatalf("GetCurrentKey() error: %v", err)
	}

	keyStr, ok := key.(string)
	if !ok {
		t.Fatal("Key should be string type")
	}
	if keyStr != "key1" {
		t.Errorf("GetCurrentKey() = %s, want key1", keyStr)
	}
}

func TestManager_GetCurrentKey_Censys(t *testing.T) {
	m := NewManager(true)
	creds := []CensysCredential{
		{ID: "id1", Secret: "secret1"},
	}
	m.SetCensysCreds(creds)

	cred, err := m.GetCurrentKey(SourceCensys)
	if err != nil {
		t.Fatalf("GetCurrentKey() error: %v", err)
	}

	credObj, ok := cred.(CensysCredential)
	if !ok {
		t.Fatal("Credential should be CensysCredential type")
	}
	if credObj.ID != "id1" {
		t.Errorf("Credential ID = %s, want id1", credObj.ID)
	}
}

func TestManager_GetCurrentKey_NoKeys(t *testing.T) {
	m := NewManager(true)

	_, err := m.GetCurrentKey(SourceShodan)
	if err == nil {
		t.Error("GetCurrentKey() should error when no keys configured")
	}
}

func TestManager_RotateKey(t *testing.T) {
	m := NewManager(true)
	keys := []string{"key1", "key2", "key3"}
	m.SetShodanKeys(keys)

	// First rotation
	rotated := m.RotateKey(SourceShodan)
	if !rotated {
		t.Error("First rotation should succeed")
	}

	key, _ := m.GetCurrentKey(SourceShodan)
	if key.(string) != "key2" {
		t.Errorf("After rotation, key = %s, want key2", key.(string))
	}

	// Second rotation
	rotated = m.RotateKey(SourceShodan)
	if !rotated {
		t.Error("Second rotation should succeed")
	}

	// Third rotation (should fail - no more keys)
	rotated = m.RotateKey(SourceShodan)
	if rotated {
		t.Error("Third rotation should fail (all keys exhausted)")
	}
}

func TestManager_ResetKeyRotation(t *testing.T) {
	m := NewManager(true)
	keys := []string{"key1", "key2"}
	m.SetShodanKeys(keys)

	// Rotate once
	m.RotateKey(SourceShodan)

	// Reset
	m.ResetKeyRotation(SourceShodan)

	// Should be back to first key
	key, _ := m.GetCurrentKey(SourceShodan)
	if key.(string) != "key1" {
		t.Errorf("After reset, key = %s, want key1", key.(string))
	}
}

func TestManager_RegisterSource(t *testing.T) {
	m := NewManager(true)

	m.RegisterSource(SourceShodan)

	status, err := m.GetStatus(SourceShodan)
	if err != nil {
		t.Fatalf("GetStatus() error: %v", err)
	}

	if status.Source != SourceShodan {
		t.Errorf("Source = %s, want %s", status.Source, SourceShodan)
	}
	if status.Status != StatusUnchecked {
		t.Errorf("Status = %s, want %s", status.Status, StatusUnchecked)
	}
}

func TestManager_ValidateSource_Success(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)

	validator := func(ctx context.Context) error {
		return nil // Success
	}

	err := m.ValidateSource(context.Background(), SourceShodan, validator)
	if err != nil {
		t.Fatalf("ValidateSource() error: %v", err)
	}

	status, _ := m.GetStatus(SourceShodan)
	if status.Status != StatusAvailable {
		t.Errorf("Status = %s, want %s", status.Status, StatusAvailable)
	}
	if status.LastError != nil {
		t.Errorf("LastError should be nil, got: %v", status.LastError)
	}
}

func TestManager_ValidateSource_Error(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)

	expectedErr := errors.New("API error")
	validator := func(ctx context.Context) error {
		return expectedErr
	}

	err := m.ValidateSource(context.Background(), SourceShodan, validator)
	if err == nil {
		t.Fatal("ValidateSource() should return error")
	}

	status, _ := m.GetStatus(SourceShodan)
	if status.Status != StatusError {
		t.Errorf("Status = %s, want %s", status.Status, StatusError)
	}
	if status.LastError == nil {
		t.Error("LastError should not be nil")
	}
}

func TestManager_ValidateSource_RateLimit(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)

	rateLimitErr := errors.New("rate limit exceeded")
	validator := func(ctx context.Context) error {
		return rateLimitErr
	}

	err := m.ValidateSource(context.Background(), SourceShodan, validator)
	if err == nil {
		t.Fatal("ValidateSource() should return error")
	}

	status, _ := m.GetStatus(SourceShodan)
	if status.Status != StatusRateLimited {
		t.Errorf("Status = %s, want %s", status.Status, StatusRateLimited)
	}
	if status.RateLimitEnd.IsZero() {
		t.Error("RateLimitEnd should be set")
	}
}

func TestManager_GetAvailableSources(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)
	m.RegisterSource(SourceCensys)
	m.RegisterSource(SourceCT)

	// Initially all should be available (unchecked)
	available := m.GetAvailableSources()
	if len(available) != 3 {
		t.Errorf("Available sources = %d, want 3", len(available))
	}

	// Mark one as rate limited
	m.sources[SourceShodan].mu.Lock()
	m.sources[SourceShodan].Status = StatusRateLimited
	m.sources[SourceShodan].RateLimitEnd = time.Now().Add(1 * time.Hour)
	m.sources[SourceShodan].mu.Unlock()

	available = m.GetAvailableSources()
	if len(available) != 2 {
		t.Errorf("After rate limit, available = %d, want 2", len(available))
	}
}

func TestManager_MarkRateLimited_WithRotation(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)
	keys := []string{"key1", "key2"}
	m.SetShodanKeys(keys)

	// Mark as rate limited (should rotate)
	rotated := m.MarkRateLimited(SourceShodan, 1*time.Hour)
	if !rotated {
		t.Error("Should rotate to next key")
	}

	// Current key should be key2
	key, _ := m.GetCurrentKey(SourceShodan)
	if key.(string) != "key2" {
		t.Errorf("After rotation, key = %s, want key2", key.(string))
	}
}

func TestManager_MarkRateLimited_NoMoreKeys(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)
	keys := []string{"key1"}
	m.SetShodanKeys(keys)

	// Mark as rate limited (no more keys)
	rotated := m.MarkRateLimited(SourceShodan, 1*time.Hour)
	if rotated {
		t.Error("Should not rotate (no more keys)")
	}

	status, _ := m.GetStatus(SourceShodan)
	if status.Status != StatusRateLimited {
		t.Errorf("Status = %s, want %s", status.Status, StatusRateLimited)
	}
}

func TestManager_IncrementRequests(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)

	m.IncrementRequests(SourceShodan)
	m.IncrementRequests(SourceShodan)
	m.IncrementRequests(SourceShodan)

	status, _ := m.GetStatus(SourceShodan)
	if status.RequestsMade != 3 {
		t.Errorf("RequestsMade = %d, want 3", status.RequestsMade)
	}
}

func TestManager_GetNextAvailableSource_WithFailover(t *testing.T) {
	m := NewManager(true) // Failover enabled
	m.RegisterSource(SourceShodan)
	m.RegisterSource(SourceCensys)
	m.RegisterSource(SourceCT)

	next := m.GetNextAvailableSource(SourceShodan)
	if next == "" {
		t.Error("Should return next source with failover enabled")
	}
}

func TestManager_GetNextAvailableSource_NoFailover(t *testing.T) {
	m := NewManager(false) // Failover disabled
	m.RegisterSource(SourceShodan)
	m.RegisterSource(SourceCensys)

	next := m.GetNextAvailableSource(SourceShodan)
	if next != "" {
		t.Error("Should return empty string with failover disabled")
	}
}

func TestManager_AllStatus(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)
	m.RegisterSource(SourceCensys)

	allStatus := m.AllStatus()
	if len(allStatus) != 2 {
		t.Errorf("AllStatus count = %d, want 2", len(allStatus))
	}

	if _, exists := allStatus[SourceShodan]; !exists {
		t.Error("Shodan should be in status map")
	}
	if _, exists := allStatus[SourceCensys]; !exists {
		t.Error("Censys should be in status map")
	}
}

func TestIsRateLimitError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"rate limit", errors.New("rate limit exceeded"), true},
		{"429 status", errors.New("HTTP 429"), true},
		{"too many requests", errors.New("too many requests"), true},
		{"quota exceeded", errors.New("quota exceeded"), true},
		{"other error", errors.New("network error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRateLimitError(tt.err)
			if got != tt.want {
				t.Errorf("isRateLimitError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{"found lowercase", "hello world", "world", true},
		{"found uppercase", "HELLO WORLD", "world", true},
		{"not found", "hello", "xyz", false},
		{"empty substring", "hello", "", true},
		{"case insensitive", "Rate Limit", "rate limit", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"already lowercase", "hello", "hello"},
		{"uppercase", "HELLO", "hello"},
		{"mixed case", "HeLLo WoRLd", "hello world"},
		{"numbers", "Test123", "test123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toLower(tt.input)
			if got != tt.want {
				t.Errorf("toLower(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindSubstring(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{"found at start", "hello world", "hello", true},
		{"found at end", "hello world", "world", true},
		{"found in middle", "hello world", "lo wo", true},
		{"not found", "hello", "xyz", false},
		{"empty substring", "hello", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findSubstring(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("findSubstring(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestAPIStatus_Constants(t *testing.T) {
	if StatusAvailable != "available" {
		t.Error("StatusAvailable constant mismatch")
	}
	if StatusRateLimited != "rate_limited" {
		t.Error("StatusRateLimited constant mismatch")
	}
	if StatusError != "error" {
		t.Error("StatusError constant mismatch")
	}
	if StatusUnchecked != "unchecked" {
		t.Error("StatusUnchecked constant mismatch")
	}
	if StatusDisabled != "disabled" {
		t.Error("StatusDisabled constant mismatch")
	}
}

func TestSource_Constants(t *testing.T) {
	if SourceShodan != "shodan" {
		t.Error("SourceShodan constant mismatch")
	}
	if SourceCensys != "censys" {
		t.Error("SourceCensys constant mismatch")
	}
	if SourceCT != "ct" {
		t.Error("SourceCT constant mismatch")
	}
	if SourceDNS != "dns" {
		t.Error("SourceDNS constant mismatch")
	}
}

func TestManager_ConcurrentAccess(t *testing.T) {
	m := NewManager(true)
	m.RegisterSource(SourceShodan)
	keys := []string{"key1", "key2", "key3"}
	m.SetShodanKeys(keys)

	// Concurrent access test
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			m.GetCurrentKey(SourceShodan)
			m.IncrementRequests(SourceShodan)
			m.GetStatus(SourceShodan)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCensysCredential_Structure(t *testing.T) {
	cred := CensysCredential{
		ID:     "test_id",
		Secret: "test_secret",
	}

	if cred.ID != "test_id" {
		t.Errorf("ID = %s, want test_id", cred.ID)
	}
	if cred.Secret != "test_secret" {
		t.Errorf("Secret = %s, want test_secret", cred.Secret)
	}
}

