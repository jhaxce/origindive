package ip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseInputFile(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		content   string
		wantCount int
		wantErr   bool
	}{
		{
			name: "single IPs",
			content: `192.168.1.1
192.168.1.2
10.0.0.1`,
			wantCount: 3,
			wantErr:   false,
		},
		{
			name: "CIDR ranges",
			content: `192.168.1.0/24
10.0.0.0/30`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "IP ranges",
			content: `192.168.1.1-192.168.1.10
10.0.0.1-10.0.0.5`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "mixed formats",
			content: `# Comment line
192.168.1.1
192.168.1.0/24
10.0.0.1-10.0.0.5

# Another comment
8.8.8.8`,
			wantCount: 4,
			wantErr:   false,
		},
		{
			name: "blank lines and comments",
			content: `# This is a comment

192.168.1.1

# Another comment
10.0.0.1

`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "invalid IP",
			content: `192.168.1.1
999.999.999.999
10.0.0.1`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "invalid CIDR",
			content: `192.168.1.1
192.168.1.0/33
10.0.0.1`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "invalid IP range",
			content:   `192.168.1.1-192.168.1.10-192.168.1.20`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "empty file",
			content: `# Only comments

`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "IPv6 (should fail)",
			content:   `2001:db8::1`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "comments only",
			content:   "# Comment 1\n# Comment 2",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "windows line endings",
			content:   "192.168.1.1\r\n192.168.1.2\r\n10.0.0.1\r\n",
			wantCount: 3,
			wantErr:   false,
		},
		{
			name:      "/31 CIDR",
			content:   `192.168.1.0/31`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "/32 CIDR",
			content:   `192.168.1.1/32`,
			wantCount: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			filePath := filepath.Join(tmpDir, "test.txt")
			err := os.WriteFile(filePath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			defer os.Remove(filePath)

			// Parse file
			ranges, err := ParseInputFile(filePath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseInputFile() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseInputFile() unexpected error: %v", err)
				return
			}

			if len(ranges) != tt.wantCount {
				t.Errorf("ParseInputFile() got %d ranges, want %d", len(ranges), tt.wantCount)
			}
		})
	}
}

func TestParseInputFile_FileNotFound(t *testing.T) {
	_, err := ParseInputFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("ParseInputFile() expected error for nonexistent file, got nil")
	}
}

func TestParseInputFile_ValidRanges(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "ranges.txt")

	content := `192.168.1.1
192.168.1.0/30
10.0.0.1-10.0.0.5`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	ranges, err := ParseInputFile(filePath)
	if err != nil {
		t.Fatalf("ParseInputFile() error: %v", err)
	}

	if len(ranges) != 3 {
		t.Fatalf("ParseInputFile() got %d ranges, want 3", len(ranges))
	}

	// Test single IP (192.168.1.1)
	if ranges[0].Start != ranges[0].End {
		t.Errorf("Single IP should have Start == End")
	}

	// Test CIDR (192.168.1.0/30 = 2 usable IPs, excluding network and broadcast)
	cidrCount := ranges[1].Count()
	if cidrCount != 2 {
		t.Errorf("CIDR /30 got %d IPs, want 2", cidrCount)
	}

	// Test IP range (10.0.0.1-10.0.0.5 = 5 IPs)
	rangeCount := ranges[2].Count()
	if rangeCount != 5 {
		t.Errorf("IP range got %d IPs, want 5", rangeCount)
	}
}

func TestParseInputFile_ErrorLineNumbers(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "error.txt")

	content := `192.168.1.1
192.168.1.2
invalid_ip
192.168.1.4`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = ParseInputFile(filePath)
	if err == nil {
		t.Fatal("ParseInputFile() expected error for invalid IP")
	}

	// Error message should contain line number
	errMsg := err.Error()
	if !containsString(errMsg, "line 3") {
		t.Errorf("Error message should contain 'line 3', got: %s", errMsg)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || len(s) > len(substr)+1 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
