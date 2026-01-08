package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Mode != ModeActive {
		t.Errorf("Mode = %s, want %s", config.Mode, ModeActive)
	}
	if config.HTTPMethod != "GET" {
		t.Errorf("HTTPMethod = %s, want GET", config.HTTPMethod)
	}
	if config.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", config.Timeout)
	}
	if config.ConnectTimeout != 3*time.Second {
		t.Errorf("ConnectTimeout = %v, want 3s", config.ConnectTimeout)
	}
	if config.Workers != 10 {
		t.Errorf("Workers = %d, want 10", config.Workers)
	}
	if config.Format != FormatText {
		t.Errorf("Format = %s, want %s", config.Format, FormatText)
	}
	if config.MinConfidence != 0.7 {
		t.Errorf("MinConfidence = %f, want 0.7", config.MinConfidence)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr error
	}{
		{
			name:    "No domain",
			config:  &Config{},
			wantErr: ErrNoDomain,
		},
		{
			name: "Valid config",
			config: &Config{
				Domain:  "example.com",
				Mode:    ModeActive,
				CIDR:    "192.0.2.0/24",
				Workers: 10,
			},
			wantErr: nil,
		},
		{
			name: "Too many workers",
			config: &Config{
				Domain:  "example.com",
				Workers: 1001,
			},
			wantErr: ErrTooManyWorkers,
		},
		{
			name: "Passive mode without IP range",
			config: &Config{
				Domain: "example.com",
				Mode:   ModePassive,
			},
			wantErr: nil,
		},
		{
			name: "Auto mode without IP range (valid for passive-first)",
			config: &Config{
				Domain: "example.com",
				Mode:   ModeAuto,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_WorkersAutoCorrection(t *testing.T) {
	config := &Config{
		Domain:  "example.com",
		Workers: 0,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if config.Workers != 1 {
		t.Errorf("Workers = %d, want 1 (auto-corrected)", config.Workers)
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.yaml")

	configContent := `
domain: "example.com"
mode: "active"
cidr: "192.0.2.0/24"
workers: 20
timeout: "10s"
format: "json"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	config, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if config.Domain != "example.com" {
		t.Errorf("Domain = %s, want example.com", config.Domain)
	}
	if config.Mode != ModeActive {
		t.Errorf("Mode = %s, want active", config.Mode)
	}
	if config.CIDR != "192.0.2.0/24" {
		t.Errorf("CIDR = %s, want 192.0.2.0/24", config.CIDR)
	}
	if config.Workers != 20 {
		t.Errorf("Workers = %d, want 20", config.Workers)
	}
	if config.Format != FormatJSON {
		t.Errorf("Format = %s, want json", config.Format)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Error("LoadFromFile() expected error for nonexistent file")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	invalidContent := `
domain: example.com
invalid_yaml: [unclosed
`

	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to create invalid config file: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Error("LoadFromFile() expected error for invalid YAML")
	}
}

func TestMergeWithCLI(t *testing.T) {
	fileConfig := &Config{
		Domain:  "example.com",
		Mode:    ModePassive,
		Workers: 10,
		Timeout: 5 * time.Second,
		Format:  FormatText,
	}

	cliConfig := &Config{
		Domain:  "override.com",
		Workers: 20,
		Format:  FormatJSON,
	}

	fileConfig.MergeWithCLI(cliConfig)

	if fileConfig.Domain != "override.com" {
		t.Errorf("Domain = %s, want override.com (from CLI)", fileConfig.Domain)
	}
	if fileConfig.Workers != 20 {
		t.Errorf("Workers = %d, want 20 (from CLI)", fileConfig.Workers)
	}
	if fileConfig.Format != FormatJSON {
		t.Errorf("Format = %s, want json (from CLI)", fileConfig.Format)
	}
	if fileConfig.Mode != ModePassive {
		t.Errorf("Mode = %s, want passive (from file, CLI empty)", fileConfig.Mode)
	}
}

func TestMergeWithCLI_EmptyCLIDoesNotOverride(t *testing.T) {
	fileConfig := &Config{
		Domain:  "example.com",
		Workers: 15,
	}

	cliConfig := DefaultConfig()

	fileConfig.MergeWithCLI(cliConfig)

	if fileConfig.Domain != "example.com" {
		t.Errorf("Domain = %s, want example.com (file should not be overridden)", fileConfig.Domain)
	}
	if fileConfig.Workers != 15 {
		t.Errorf("Workers = %d, want 15 (file should not be overridden)", fileConfig.Workers)
	}
}

func TestOutputFormat(t *testing.T) {
	if FormatText != "text" {
		t.Errorf("FormatText = %s, want text", FormatText)
	}
	if FormatJSON != "json" {
		t.Errorf("FormatJSON = %s, want json", FormatJSON)
	}
	if FormatCSV != "csv" {
		t.Errorf("FormatCSV = %s, want csv", FormatCSV)
	}
}

// ============================================================================
// Additional Coverage Tests for MergeWithCLI
// ============================================================================

func TestMergeWithCLI_AllBooleanFlags(t *testing.T) {
	fileConfig := DefaultConfig()
	fileConfig.Domain = "example.com"

	cliConfig := &Config{
		NoUserAgent: true,
		SkipWAF:     true,
		ShowSkipped: true,
		NoWAFUpdate: true,
		PassiveOnly: true,
		AutoScan:    true,
		Quiet:       true,
		Verbose:     true,
		ShowAll:     true,
		NoColor:     true,
		NoProgress:  true,
	}

	fileConfig.MergeWithCLI(cliConfig)

	if !fileConfig.NoUserAgent {
		t.Error("NoUserAgent not merged")
	}
	if !fileConfig.SkipWAF {
		t.Error("SkipWAF not merged")
	}
	if !fileConfig.ShowSkipped {
		t.Error("ShowSkipped not merged")
	}
	if !fileConfig.NoWAFUpdate {
		t.Error("NoWAFUpdate not merged")
	}
	if !fileConfig.PassiveOnly {
		t.Error("PassiveOnly not merged")
	}
	if !fileConfig.AutoScan {
		t.Error("AutoScan not merged")
	}
	if !fileConfig.Quiet {
		t.Error("Quiet not merged")
	}
	if !fileConfig.Verbose {
		t.Error("Verbose not merged")
	}
	if !fileConfig.ShowAll {
		t.Error("ShowAll not merged")
	}
	if !fileConfig.NoColor {
		t.Error("NoColor not merged")
	}
	if !fileConfig.NoProgress {
		t.Error("NoProgress not merged")
	}
}

func TestMergeWithCLI_StringFields(t *testing.T) {
	fileConfig := DefaultConfig()
	fileConfig.Domain = "original.com"

	cliConfig := &Config{
		Mode:          ModeAuto,
		StartIP:       "192.0.2.1",
		EndIP:         "192.0.2.254",
		CIDR:          "192.0.2.0/24",
		InputFile:     "/path/to/input.txt",
		CustomHeader:  "X-Custom: value",
		CustomWAFFile: "/path/to/waf.json",
		OutputFile:    "/path/to/output.txt",
		HTTPMethod:    "POST",
	}

	fileConfig.MergeWithCLI(cliConfig)

	if fileConfig.Mode != ModeAuto {
		t.Errorf("Mode = %s, want auto", fileConfig.Mode)
	}
	if fileConfig.StartIP != "192.0.2.1" {
		t.Errorf("StartIP = %s, want 192.0.2.1", fileConfig.StartIP)
	}
	if fileConfig.EndIP != "192.0.2.254" {
		t.Errorf("EndIP = %s, want 192.0.2.254", fileConfig.EndIP)
	}
	if fileConfig.CIDR != "192.0.2.0/24" {
		t.Errorf("CIDR = %s, want 192.0.2.0/24", fileConfig.CIDR)
	}
	if fileConfig.InputFile != "/path/to/input.txt" {
		t.Errorf("InputFile = %s", fileConfig.InputFile)
	}
	if fileConfig.CustomHeader != "X-Custom: value" {
		t.Errorf("CustomHeader = %s", fileConfig.CustomHeader)
	}
	if fileConfig.CustomWAFFile != "/path/to/waf.json" {
		t.Errorf("CustomWAFFile = %s", fileConfig.CustomWAFFile)
	}
	if fileConfig.OutputFile != "/path/to/output.txt" {
		t.Errorf("OutputFile = %s", fileConfig.OutputFile)
	}
	if fileConfig.HTTPMethod != "POST" {
		t.Errorf("HTTPMethod = %s, want POST", fileConfig.HTTPMethod)
	}
}

func TestMergeWithCLI_SliceFields(t *testing.T) {
	fileConfig := DefaultConfig()
	fileConfig.Domain = "example.com"

	cliConfig := &Config{
		SkipProviders:  []string{"cloudflare", "aws"},
		PassiveSources: []string{"shodan", "censys"},
	}

	fileConfig.MergeWithCLI(cliConfig)

	if len(fileConfig.SkipProviders) != 2 {
		t.Errorf("SkipProviders length = %d, want 2", len(fileConfig.SkipProviders))
	}
	if len(fileConfig.PassiveSources) != 2 {
		t.Errorf("PassiveSources length = %d, want 2", len(fileConfig.PassiveSources))
	}
}

func TestMergeWithCLI_TimeoutFields(t *testing.T) {
	fileConfig := DefaultConfig()
	fileConfig.Domain = "example.com"

	cliConfig := &Config{
		Timeout:        10 * time.Second, // Different from default 5s
		ConnectTimeout: 5 * time.Second,  // Different from default 3s
	}

	fileConfig.MergeWithCLI(cliConfig)

	if fileConfig.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", fileConfig.Timeout)
	}
	if fileConfig.ConnectTimeout != 5*time.Second {
		t.Errorf("ConnectTimeout = %v, want 5s", fileConfig.ConnectTimeout)
	}
}

func TestMergeWithCLI_MinConfidence(t *testing.T) {
	fileConfig := DefaultConfig()
	fileConfig.Domain = "example.com"

	cliConfig := &Config{
		MinConfidence: 0.5, // Different from default 0.7
	}

	fileConfig.MergeWithCLI(cliConfig)

	if fileConfig.MinConfidence != 0.5 {
		t.Errorf("MinConfidence = %f, want 0.5", fileConfig.MinConfidence)
	}
}

func TestValidate_ActiveModeNoIPRange(t *testing.T) {
	config := &Config{
		Domain: "example.com",
		Mode:   ModeActive,
		// No IP range provided - should fail
	}

	err := config.Validate()
	if err != ErrNoIPRange {
		t.Errorf("Validate() error = %v, want ErrNoIPRange", err)
	}
}

func TestPassiveConfig_Structure(t *testing.T) {
	config := PassiveConfig{
		ShodanKeys:         []string{"key1", "key2"},
		CensysTokens:       []string{"token1"},
		SecurityTrailsKeys: []string{"st_key"},
		ZoomEyeKeys:        []string{"ze_key"},
		DNSDumpsterKeys:    []string{"dd_key"},
		VirusTotalKeys:     []string{"vt_key"},
		ViewDNSKeys:        []string{"vd_key"},
	}

	if len(config.ShodanKeys) != 2 {
		t.Errorf("ShodanKeys length = %d, want 2", len(config.ShodanKeys))
	}
	if len(config.CensysTokens) != 1 {
		t.Errorf("CensysTokens length = %d, want 1", len(config.CensysTokens))
	}
}
