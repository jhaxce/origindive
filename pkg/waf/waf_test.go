package waf

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Test NewRangeSet
func TestNewRangeSet(t *testing.T) {
	rs := NewRangeSet()
	if rs == nil {
		t.Fatal("NewRangeSet() returned nil")
	}
	if rs.Count() != 0 {
		t.Errorf("Count() = %d, want 0", rs.Count())
	}
}

// Test AddProvider
func TestRangeSet_AddProvider(t *testing.T) {
	rs := NewRangeSet()
	provider := &Provider{
		ID:     "cloudflare",
		Name:   "Cloudflare",
		Ranges: []string{"104.16.0.0/13", "104.24.0.0/14"},
	}

	err := rs.AddProvider(provider)
	if err != nil {
		t.Fatalf("AddProvider() error: %v", err)
	}
	if rs.Count() != 2 {
		t.Errorf("Count() = %d, want 2", rs.Count())
	}
}

// Test AddProvider with nil
func TestRangeSet_AddProviderNil(t *testing.T) {
	rs := NewRangeSet()
	err := rs.AddProvider(nil)
	if err == nil {
		t.Error("AddProvider(nil) expected error")
	}
}

// Test AddProvider with invalid CIDR
func TestRangeSet_AddProviderInvalidCIDR(t *testing.T) {
	rs := NewRangeSet()
	provider := &Provider{
		ID:     "test",
		Name:   "Test",
		Ranges: []string{"invalid"},
	}
	err := rs.AddProvider(provider)
	if err == nil {
		t.Error("AddProvider() with invalid CIDR expected error")
	}
}

// Test Contains
func TestRangeSet_Contains(t *testing.T) {
	rs := NewRangeSet()
	provider := &Provider{
		ID:     "cloudflare",
		Name:   "Cloudflare",
		Ranges: []string{"104.16.0.0/13"},
	}
	rs.AddProvider(provider)

	tests := []struct {
		ip   string
		want bool
	}{
		{"104.16.0.1", true},
		{"104.23.255.255", true},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := rs.Contains(ip)
		if got != tt.want {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// Test FindProvider
func TestRangeSet_FindProvider(t *testing.T) {
	rs := NewRangeSet()
	rs.AddProvider(&Provider{
		ID:     "cloudflare",
		Name:   "Cloudflare",
		Ranges: []string{"104.16.0.0/13"},
	})
	rs.AddProvider(&Provider{
		ID:     "aws-cloudfront",
		Name:   "AWS CloudFront",
		Ranges: []string{"13.32.0.0/15"},
	})

	tests := []struct {
		ip        string
		wantFound bool
		wantID    string
	}{
		{"104.16.0.1", true, "cloudflare"},
		{"13.32.0.1", true, "aws-cloudfront"},
		{"8.8.8.8", false, ""},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		id, found := rs.FindProvider(ip)
		if found != tt.wantFound {
			t.Errorf("FindProvider(%s) found = %v, want %v", tt.ip, found, tt.wantFound)
		}
		if id != tt.wantID {
			t.Errorf("FindProvider(%s) id = %s, want %s", tt.ip, id, tt.wantID)
		}
	}
}

// Test Providers
func TestRangeSet_Providers(t *testing.T) {
	rs := NewRangeSet()
	rs.AddProvider(&Provider{ID: "cloudflare", Ranges: []string{"104.16.0.0/13"}})
	rs.AddProvider(&Provider{ID: "aws", Ranges: []string{"13.32.0.0/15"}})

	providers := rs.Providers()
	if len(providers) != 2 {
		t.Errorf("Providers() len = %d, want 2", len(providers))
	}
}

// Test LoadFromDatabase
func TestLoadFromDatabase(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{
			{ID: "cloudflare", Name: "Cloudflare", Ranges: []string{"104.16.0.0/13"}},
			{ID: "aws", Name: "AWS", Ranges: []string{"13.32.0.0/15"}},
		},
	}

	rs, err := LoadFromDatabase(db, nil)
	if err != nil {
		t.Fatalf("LoadFromDatabase() error: %v", err)
	}
	if rs.Count() != 2 {
		t.Errorf("Count() = %d, want 2", rs.Count())
	}

	// Test with specific providers
	rs2, err := LoadFromDatabase(db, []string{"cloudflare"})
	if err != nil {
		t.Fatalf("LoadFromDatabase() with filter error: %v", err)
	}
	if rs2.Count() != 1 {
		t.Errorf("Count() with filter = %d, want 1", rs2.Count())
	}
}

// Test LoadCustomRanges
func TestLoadCustomRanges(t *testing.T) {
	tmpDir := t.TempDir()

	// Test JSON format (must start with {)
	jsonFile := filepath.Join(tmpDir, "test.json")
	jsonContent := `{"providers":[{"id":"test","name":"Test","ranges":["10.0.0.0/8"]}]}`
	os.WriteFile(jsonFile, []byte(jsonContent), 0644)

	rs, err := LoadCustomRanges(jsonFile)
	if err != nil {
		t.Fatalf("LoadCustomRanges(JSON) error: %v", err)
	}
	if rs.Count() != 1 {
		t.Errorf("LoadCustomRanges(JSON) count = %d, want 1", rs.Count())
	}

	// Test text format
	txtFile := filepath.Join(tmpDir, "test.txt")
	txtContent := "# Comment\n10.0.0.0/8\n172.16.0.0/12"
	os.WriteFile(txtFile, []byte(txtContent), 0644)

	rs2, err := LoadCustomRanges(txtFile)
	if err != nil {
		t.Fatalf("LoadCustomRanges(txt) error: %v", err)
	}
	if rs2.Count() != 2 {
		t.Errorf("LoadCustomRanges(txt) count = %d, want 2", rs2.Count())
	}
}

// Test Filter
func TestNewFilter(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{{ID: "test", Ranges: []string{"104.16.0.0/13"}}},
	}
	rs, _ := LoadFromDatabase(db, nil)
	filter := NewFilter(rs, true)

	if filter == nil {
		t.Fatal("NewFilter() returned nil")
	}
	if !filter.IsEnabled() {
		t.Error("IsEnabled() = false, want true")
	}
}

func TestFilter_ShouldSkip(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{{ID: "cloudflare", Ranges: []string{"104.16.0.0/13"}}},
	}
	rs, _ := LoadFromDatabase(db, nil)
	filter := NewFilter(rs, true)

	skip, id := filter.ShouldSkip(net.ParseIP("104.16.0.1"))
	if !skip {
		t.Error("ShouldSkip(WAF IP) = false, want true")
	}
	if id != "cloudflare" {
		t.Errorf("ShouldSkip() id = %s, want cloudflare", id)
	}

	skip2, _ := filter.ShouldSkip(net.ParseIP("8.8.8.8"))
	if skip2 {
		t.Error("ShouldSkip(non-WAF IP) = true, want false")
	}
}

func TestFilter_Disabled(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{{ID: "test", Ranges: []string{"104.16.0.0/13"}}},
	}
	rs, _ := LoadFromDatabase(db, nil)
	filter := NewFilter(rs, false)

	skip, _ := filter.ShouldSkip(net.ParseIP("104.16.0.1"))
	if skip {
		t.Error("Disabled filter should not skip")
	}
}

func TestFilter_Stats(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{{ID: "test", Ranges: []string{"104.16.0.0/13"}}},
	}
	rs, _ := LoadFromDatabase(db, nil)
	filter := NewFilter(rs, true)

	filter.ShouldSkip(net.ParseIP("104.16.0.1"))
	filter.ShouldSkip(net.ParseIP("8.8.8.8"))

	stats := filter.GetStats()
	if stats.TotalChecked != 2 {
		t.Errorf("TotalChecked = %d, want 2", stats.TotalChecked)
	}
	if stats.TotalSkipped != 1 {
		t.Errorf("TotalSkipped = %d, want 1", stats.TotalSkipped)
	}
}

func TestFilter_Reset(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{{ID: "test", Ranges: []string{"104.16.0.0/13"}}},
	}
	rs, _ := LoadFromDatabase(db, nil)
	filter := NewFilter(rs, true)

	filter.ShouldSkip(net.ParseIP("104.16.0.1"))
	filter.Reset()

	stats := filter.GetStats()
	if stats.TotalChecked != 0 {
		t.Errorf("After Reset() TotalChecked = %d, want 0", stats.TotalChecked)
	}
}

func TestFilter_EnableDisable(t *testing.T) {
	filter := NewFilter(nil, true)
	if !filter.IsEnabled() {
		t.Error("IsEnabled() = false, want true")
	}

	filter.Disable()
	if filter.IsEnabled() {
		t.Error("After Disable() IsEnabled() = true, want false")
	}

	filter.Enable()
	if !filter.IsEnabled() {
		t.Error("After Enable() IsEnabled() = false, want true")
	}
}

func TestFilter_Concurrent(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{{ID: "test", Ranges: []string{"104.16.0.0/13"}}},
	}
	rs, _ := LoadFromDatabase(db, nil)
	filter := NewFilter(rs, true)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				filter.ShouldSkip(net.ParseIP("104.16.0.1"))
			}
		}()
	}
	wg.Wait()

	stats := filter.GetStats()
	if stats.TotalChecked != 1000 {
		t.Errorf("Concurrent TotalChecked = %d, want 1000", stats.TotalChecked)
	}
}

func TestFilterStats_String(t *testing.T) {
	stats := FilterStats{
		TotalChecked: 100,
		TotalSkipped: 25,
		ByProvider:   map[string]uint64{"test": 25},
	}
	s := stats.String()
	if s == "" {
		t.Error("String() returned empty")
	}
}

func TestFilter_ShouldSkipString(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{{ID: "test", Ranges: []string{"104.16.0.0/13"}}},
	}
	rs, _ := LoadFromDatabase(db, nil)
	filter := NewFilter(rs, true)

	skip, _ := filter.ShouldSkipString("104.16.0.1")
	if !skip {
		t.Error("ShouldSkipString(WAF IP) = false, want true")
	}

	skip2, _ := filter.ShouldSkipString("invalid")
	if skip2 {
		t.Error("ShouldSkipString(invalid) = true, want false")
	}
}

// Test LoadUpdateConfig
func TestLoadUpdateConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "update_config.json")

	_ = os.WriteFile(configPath, []byte(`{
		"update_interval_hours": 24,
		"sources": [{
			"provider": "test-provider",
			"url": "https://example.com/ranges.txt",
			"format": "text",
			"description": "Test provider"
		}]
	}`), 0644)

	loaded, err := LoadUpdateConfig(configPath)
	if err != nil {
		t.Fatalf("LoadUpdateConfig() error: %v", err)
	}

	if loaded.UpdateIntervalHours != 24 {
		t.Errorf("UpdateIntervalHours = %d, want 24", loaded.UpdateIntervalHours)
	}
	if len(loaded.Sources) != 1 {
		t.Errorf("Sources count = %d, want 1", len(loaded.Sources))
	}
}

// Test LoadUpdateConfig with non-existent file
func TestLoadUpdateConfig_NotFound(t *testing.T) {
	_, err := LoadUpdateConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("LoadUpdateConfig() expected error for non-existent file")
	}
}

// Test LoadUpdateConfig with invalid JSON
func TestLoadUpdateConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.json")
	os.WriteFile(configPath, []byte("{invalid json"), 0644)

	_, err := LoadUpdateConfig(configPath)
	if err == nil {
		t.Error("LoadUpdateConfig() expected error for invalid JSON")
	}
}

// Test NewUpdater
func TestNewUpdater(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	dbPath := filepath.Join(tmpDir, "db.json")

	os.WriteFile(configPath, []byte(`{
		"update_interval_hours": 24,
		"sources": []
	}`), 0644)

	updater, err := NewUpdater(configPath, dbPath)
	if err != nil {
		t.Fatalf("NewUpdater() error: %v", err)
	}

	if updater.dbPath != dbPath {
		t.Errorf("dbPath = %s, want %s", updater.dbPath, dbPath)
	}
}

// Test NewUpdater with invalid config
func TestNewUpdater_InvalidConfig(t *testing.T) {
	_, err := NewUpdater("/nonexistent/config.json", "/tmp/db.json")
	if err == nil {
		t.Error("NewUpdater() expected error for invalid config path")
	}
}

// Test Updater parseTextRanges
func TestUpdater_ParseTextRanges(t *testing.T) {
	u := &Updater{}

	data := []byte(`192.168.1.0/24
10.0.0.0/8
# This is a comment
172.16.0.0/12

`)

	ranges := u.parseTextRanges(data)
	if len(ranges) != 3 {
		t.Errorf("parseTextRanges() count = %d, want 3", len(ranges))
	}

	expected := map[string]bool{
		"192.168.1.0/24": true,
		"10.0.0.0/8":     true,
		"172.16.0.0/12":  true,
	}

	for _, r := range ranges {
		if !expected[r] {
			t.Errorf("Unexpected range: %s", r)
		}
	}
}

// Test Updater parseAWSRanges
func TestUpdater_ParseAWSRanges(t *testing.T) {
	u := &Updater{}

	data := []byte(`{
		"prefixes": [
			{"ip_prefix": "192.0.2.0/24", "service": "CLOUDFRONT"},
			{"ip_prefix": "198.51.100.0/24", "service": "EC2"},
			{"ip_prefix": "203.0.113.0/24", "service": "CLOUDFRONT"}
		]
	}`)

	ranges, err := u.parseAWSRanges(data)
	if err != nil {
		t.Fatalf("parseAWSRanges() error: %v", err)
	}

	if len(ranges) != 2 {
		t.Errorf("parseAWSRanges() count = %d, want 2", len(ranges))
	}
}

// Test Updater parseFastlyRanges
func TestUpdater_ParseFastlyRanges(t *testing.T) {
	u := &Updater{}

	data := []byte(`{
		"addresses": ["192.0.2.0/24", "198.51.100.0/24"]
	}`)

	ranges, err := u.parseFastlyRanges(data)
	if err != nil {
		t.Fatalf("parseFastlyRanges() error: %v", err)
	}

	if len(ranges) != 2 {
		t.Errorf("parseFastlyRanges() count = %d, want 2", len(ranges))
	}
}

// Test UpdateSource structure
func TestUpdateSource_Structure(t *testing.T) {
	source := UpdateSource{
		Provider:    "cloudflare",
		URL:         "https://api.cloudflare.com/client/v4/ips",
		IPv4URL:     "https://www.cloudflare.com/ips-v4",
		IPv6URL:     "https://www.cloudflare.com/ips-v6",
		Format:      "text",
		JSONPath:    "",
		Description: "Cloudflare CDN IP ranges",
	}

	if source.Provider != "cloudflare" {
		t.Errorf("Provider = %s", source.Provider)
	}
	if source.Format != "text" {
		t.Errorf("Format = %s", source.Format)
	}
}

// TestLoadWAFDatabase tests loading WAF database from file
func TestLoadWAFDatabase(t *testing.T) {
	// Use the actual database file
	db, err := LoadWAFDatabase("../../data/waf_ranges.json")
	if err != nil {
		t.Fatalf("LoadWAFDatabase() error: %v", err)
	}

	if db == nil {
		t.Fatal("LoadWAFDatabase() returned nil")
	}

	if len(db.Providers) == 0 {
		t.Error("Expected providers in database")
	}
}

// TestLoadWAFDatabase_NotFound tests loading non-existent file
func TestLoadWAFDatabase_NotFound(t *testing.T) {
	_, err := LoadWAFDatabase("nonexistent.json")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

// TestSaveWAFDatabase tests saving WAF database
func TestSaveWAFDatabase(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{
			{
				ID:     "test",
				Name:   "Test Provider",
				Ranges: []string{"192.168.1.0/24"},
			},
		},
	}

	tmpFile := "test_waf_db.json"
	defer os.Remove(tmpFile)

	err := SaveWAFDatabase(tmpFile, db)
	if err != nil {
		t.Fatalf("SaveWAFDatabase() error: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Error("File was not created")
	}

	// Load it back
	loaded, err := LoadWAFDatabase(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load saved database: %v", err)
	}

	if len(loaded.Providers) != 1 {
		t.Errorf("Expected 1 provider, got %d", len(loaded.Providers))
	}
}

// TestWAFDatabase_GetProvider tests GetProvider method
func TestWAFDatabase_GetProvider(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{
			{ID: "cloudflare", Name: "Cloudflare"},
			{ID: "aws", Name: "AWS CloudFront"},
		},
	}

	tests := []struct {
		id    string
		found bool
	}{
		{"cloudflare", true},
		{"aws", true},
		{"nonexistent", false},
		{"", false},
	}

	for _, tt := range tests {
		provider := db.GetProvider(tt.id)
		if tt.found && provider == nil {
			t.Errorf("GetProvider(%q) returned nil, want provider", tt.id)
		}
		if !tt.found && provider != nil {
			t.Errorf("GetProvider(%q) returned %v, want nil", tt.id, provider)
		}
	}
}

// TestWAFDatabase_GetProviderByName tests GetProviderByName method
func TestWAFDatabase_GetProviderByName(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{
			{ID: "cloudflare", Name: "Cloudflare"},
			{ID: "aws", Name: "AWS CloudFront"},
		},
	}

	tests := []struct {
		name  string
		found bool
	}{
		{"Cloudflare", true},
		{"cloudflare", true},
		{"CLOUDFLARE", true},
		{"aws", true},
		{"AWS CloudFront", true},
		{"nonexistent", false},
	}

	for _, tt := range tests {
		provider := db.GetProviderByName(tt.name)
		if tt.found && provider == nil {
			t.Errorf("GetProviderByName(%q) returned nil, want provider", tt.name)
		}
		if !tt.found && provider != nil {
			t.Errorf("GetProviderByName(%q) returned %v, want nil", tt.name, provider)
		}
	}
}

// TestWAFDatabase_ListProviders tests ListProviders method
func TestWAFDatabase_ListProviders(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{
			{ID: "cloudflare"},
			{ID: "aws"},
			{ID: "fastly"},
		},
	}

	ids := db.ListProviders()
	if len(ids) != 3 {
		t.Errorf("Expected 3 provider IDs, got %d", len(ids))
	}

	expected := map[string]bool{"cloudflare": true, "aws": true, "fastly": true}
	for _, id := range ids {
		if !expected[id] {
			t.Errorf("Unexpected provider ID: %s", id)
		}
	}
}

// TestWAFDatabase_GetTotalRanges tests GetTotalRanges method
func TestWAFDatabase_GetTotalRanges(t *testing.T) {
	db := &WAFDatabase{
		Providers: []Provider{
			{Ranges: []string{"192.168.1.0/24", "10.0.0.0/8"}},
			{Ranges: []string{"172.16.0.0/12"}},
		},
	}

	total := db.GetTotalRanges()
	if total != 3 {
		t.Errorf("GetTotalRanges() = %d, want 3", total)
	}
}

// TestWAFDatabase_ValidateRanges tests ValidateRanges method
func TestWAFDatabase_ValidateRanges(t *testing.T) {
	tests := []struct {
		name    string
		db      *WAFDatabase
		wantErr bool
	}{
		{
			name: "valid ranges",
			db: &WAFDatabase{
				Providers: []Provider{
					{ID: "test", Ranges: []string{"192.168.1.0/24", "10.0.0.0/8"}},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid CIDR",
			db: &WAFDatabase{
				Providers: []Provider{
					{ID: "test", Ranges: []string{"invalid-cidr"}},
				},
			},
			wantErr: true,
		},
		{
			name: "mixed valid and invalid",
			db: &WAFDatabase{
				Providers: []Provider{
					{ID: "test", Ranges: []string{"192.168.1.0/24", "not-a-cidr"}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.db.ValidateRanges()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRanges() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
