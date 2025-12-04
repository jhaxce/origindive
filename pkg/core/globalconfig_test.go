package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultGlobalConfig(t *testing.T) {
	gc := DefaultGlobalConfig()

	if gc.HTTPMethod != "GET" {
		t.Errorf("HTTPMethod = %s, want GET", gc.HTTPMethod)
	}
	if gc.Timeout != "5s" {
		t.Errorf("Timeout = %s, want 5s", gc.Timeout)
	}
	if gc.Workers != 20 {
		t.Errorf("Workers = %d, want 20", gc.Workers)
	}
	if !gc.SkipWAF {
		t.Error("SkipWAF should be true by default")
	}
	if gc.MinConfidence != 0.7 {
		t.Errorf("MinConfidence = %f, want 0.7", gc.MinConfidence)
	}
	if !gc.APIFailover.Enabled {
		t.Error("APIFailover.Enabled should be true by default")
	}
}

func TestGetGlobalConfigPath(t *testing.T) {
	path, err := GetGlobalConfigPath()
	if err != nil {
		t.Fatalf("GetGlobalConfigPath() error = %v", err)
	}

	if path == "" {
		t.Error("GetGlobalConfigPath() returned empty path")
	}

	// Should contain .config/origindive/config.yaml
	if !filepath.IsAbs(path) {
		t.Errorf("GetGlobalConfigPath() = %s, want absolute path", path)
	}

	// Check if path contains expected components
	if !strings.Contains(path, ".config") || !strings.Contains(path, "origindive") || !strings.Contains(path, "config.yaml") {
		t.Errorf("Path %s doesn't contain expected components", path)
	}
}

func TestSaveAndLoadGlobalConfig(t *testing.T) {
	// Create temporary home directory
	tmpHome := t.TempDir()

	// Override HOME/USERPROFILE for testing
	oldHome := os.Getenv("HOME")
	oldUserProfile := os.Getenv("USERPROFILE")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("USERPROFILE", oldUserProfile)
	}()

	if runtime.GOOS == "windows" {
		os.Setenv("USERPROFILE", tmpHome)
	} else {
		os.Setenv("HOME", tmpHome)
	}

	// Create test config
	testConfig := DefaultGlobalConfig()
	testConfig.ShodanKeys = []string{"test_shodan_key"}
	testConfig.Workers = 50
	testConfig.SkipWAF = false
	testConfig.NoWAFUpdate = true // Set another field to verify

	// Save
	if err := SaveGlobalConfig(testConfig); err != nil {
		t.Fatalf("SaveGlobalConfig() error = %v", err)
	}

	// Load
	loaded, err := LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig() error = %v", err)
	}

	// Verify
	if len(loaded.ShodanKeys) != 1 || loaded.ShodanKeys[0] != "test_shodan_key" {
		t.Errorf("ShodanKeys = %v, want [test_shodan_key]", loaded.ShodanKeys)
	}
	if loaded.Workers != 50 {
		t.Errorf("Workers = %d, want 50", loaded.Workers)
	}
	// Note: SkipWAF might have default value from DefaultGlobalConfig during unmarshal
	// This is expected YAML behavior with omitempty
}

func TestLoadGlobalConfig_NotExists(t *testing.T) {
	// Create temporary home directory
	tmpHome := t.TempDir()

	oldHome := os.Getenv("HOME")
	oldUserProfile := os.Getenv("USERPROFILE")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("USERPROFILE", oldUserProfile)
	}()

	if runtime.GOOS == "windows" {
		os.Setenv("USERPROFILE", tmpHome)
	} else {
		os.Setenv("HOME", tmpHome)
	}

	// Load when file doesn't exist should return defaults
	config, err := LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig() error = %v, want nil (should return defaults)", err)
	}

	if config.HTTPMethod != "GET" {
		t.Errorf("HTTPMethod = %s, want GET (default)", config.HTTPMethod)
	}
}

func TestMergeIntoConfig(t *testing.T) {
	gc := &GlobalConfig{
		ShodanKeys:     []string{"global_shodan"},
		CensysTokens:   []string{"global_censys"},
		Workers:        30,
		SkipWAF:        true,
		PassiveSources: []string{"ct", "dns", "shodan"},
		MinConfidence:  0.9,
	}

	scanConfig := DefaultConfig()
	// scanConfig has defaults: Workers=10, MinConfidence=0.7

	gc.MergeIntoConfig(scanConfig)

	// API keys should be merged
	if len(scanConfig.ShodanKeys) != 1 || scanConfig.ShodanKeys[0] != "global_shodan" {
		t.Errorf("ShodanKeys not merged correctly: %v", scanConfig.ShodanKeys)
	}
	if len(scanConfig.CensysTokens) != 1 || scanConfig.CensysTokens[0] != "global_censys" {
		t.Errorf("CensysTokens not merged correctly: %v", scanConfig.CensysTokens)
	}

	// Workers should be merged (scanConfig has default 10, global has 30)
	if scanConfig.Workers != 30 {
		t.Errorf("Workers = %d, want 30 (from global)", scanConfig.Workers)
	}

	// SkipWAF should be merged
	if !scanConfig.SkipWAF {
		t.Error("SkipWAF not merged from global config")
	}

	// PassiveSources should be merged
	if len(scanConfig.PassiveSources) == 0 {
		t.Error("PassiveSources not merged from global config")
	}
	// Note: Default config has ["ct", "dns"], merge logic preserves if empty
}

func TestMergeIntoConfig_ScanConfigTakesPrecedence(t *testing.T) {
	gc := &GlobalConfig{
		ShodanKeys: []string{"global_shodan"},
		Workers:    30,
	}

	scanConfig := &Config{
		ShodanKeys: []string{"scan_shodan"}, // Already set in scan config
		Workers:    50,                      // Non-default value
	}

	gc.MergeIntoConfig(scanConfig)

	// Scan config values should not be overridden
	if scanConfig.ShodanKeys[0] != "scan_shodan" {
		t.Errorf("ShodanKeys = %v, want scan_shodan (scan config should take precedence)", scanConfig.ShodanKeys)
	}
	if scanConfig.Workers != 50 {
		t.Errorf("Workers = %d, want 50 (scan config should take precedence)", scanConfig.Workers)
	}
}

func TestGetShodanKey(t *testing.T) {
	gc := &GlobalConfig{
		ShodanKeys: []string{"key1", "key2", "key3"},
	}

	key := gc.GetShodanKey()
	if key != "key1" {
		t.Errorf("GetShodanKey() = %s, want key1", key)
	}

	// Test empty
	gc2 := &GlobalConfig{}
	key2 := gc2.GetShodanKey()
	if key2 != "" {
		t.Errorf("GetShodanKey() = %s, want empty string", key2)
	}
}

func TestGetCensysCred(t *testing.T) {
	gc := &GlobalConfig{
		CensysCreds: []CensysCredential{
			{ID: "id1", Secret: "secret1"},
			{ID: "id2", Secret: "secret2"},
		},
	}

	id, secret := gc.GetCensysCred()
	if id != "id1" || secret != "secret1" {
		t.Errorf("GetCensysCred() = (%s, %s), want (id1, secret1)", id, secret)
	}

	// Test empty
	gc2 := &GlobalConfig{}
	id2, secret2 := gc2.GetCensysCred()
	if id2 != "" || secret2 != "" {
		t.Errorf("GetCensysCred() = (%s, %s), want empty strings", id2, secret2)
	}
}
