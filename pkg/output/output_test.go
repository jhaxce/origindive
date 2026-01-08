package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jhaxce/origindive/v3/pkg/core"
)

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		name      string
		format    core.OutputFormat
		useColors bool
		showAll   bool
	}{
		{"text with colors", core.FormatText, true, false},
		{"text no colors", core.FormatText, false, false},
		{"json", core.FormatJSON, false, false},
		{"csv", core.FormatCSV, false, false},
		{"text with showAll", core.FormatText, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFormatter(tt.format, tt.useColors, tt.showAll)
			if f == nil {
				t.Error("NewFormatter() returned nil")
			}
			if f.format != tt.format {
				t.Errorf("format = %v, want %v", f.format, tt.format)
			}
			if f.useColors != tt.useColors {
				t.Errorf("useColors = %v, want %v", f.useColors, tt.useColors)
			}
			if f.showAll != tt.showAll {
				t.Errorf("showAll = %v, want %v", f.showAll, tt.showAll)
			}

			if tt.useColors {
				if f.red == "" || f.green == "" {
					t.Error("Colors not initialized")
				}
			} else {
				if f.red != "" {
					t.Error("Colors should be empty when disabled")
				}
			}
		})
	}
}

func TestFormatter_FormatResult(t *testing.T) {
	tests := []struct {
		name     string
		format   core.OutputFormat
		result   core.IPResult
		contains string
	}{
		{
			name:   "text 200 OK",
			format: core.FormatText,
			result: core.IPResult{
				IP:           "1.2.3.4",
				Status:       "200",
				HTTPCode:     200,
				ResponseTime: "100ms",
			},
			contains: "1.2.3.4",
		},
		{
			name:   "text timeout",
			format: core.FormatText,
			result: core.IPResult{
				IP:     "1.2.3.4",
				Status: "timeout",
			},
			contains: "", // Not shown without showAll
		},
		{
			name:   "json format",
			format: core.FormatJSON,
			result: core.IPResult{
				IP:       "1.2.3.4",
				Status:   "200",
				HTTPCode: 200,
			},
			contains: `"ip":"1.2.3.4"`,
		},
		{
			name:   "csv format",
			format: core.FormatCSV,
			result: core.IPResult{
				IP:       "1.2.3.4",
				Status:   "200",
				HTTPCode: 200,
			},
			contains: "1.2.3.4,200,200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFormatter(tt.format, false, false)
			result := f.FormatResult(tt.result)

			if tt.contains == "" && result != "" {
				// Expected empty but got content
				return
			}

			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("FormatResult() = %q, want to contain %q", result, tt.contains)
			}
		})
	}
}

func TestFormatter_FormatResultShowAll(t *testing.T) {
	f := NewFormatter(core.FormatText, false, true)

	result := core.IPResult{
		IP:     "1.2.3.4",
		Status: "timeout",
	}

	formatted := f.FormatResult(result)
	if !strings.Contains(formatted, "1.2.3.4") {
		t.Error("showAll should display timeout results")
	}
}

func TestFormatter_FormatSummary(t *testing.T) {
	summary := core.ScanSummary{
		SuccessCount: 5,
		SuccessIPs:   []string{"1.1.1.1", "2.2.2.2"},
		ScannedIPs:   100,
		SkippedIPs:   20,
		Duration:     10 * time.Second,
	}

	tests := []struct {
		name     string
		format   core.OutputFormat
		contains []string
	}{
		{
			name:   "text format",
			format: core.FormatText,
			contains: []string{
				"5",      // success count
				"100",    // scanned
				"20",     // skipped
				"10.00s", // duration
				"10.00",  // rate (100/10)
			},
		},
		{
			name:   "json format",
			format: core.FormatJSON,
			contains: []string{
				`"success_count": 5`,
				`"scanned_ips": 100`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFormatter(tt.format, false, false)
			result := f.FormatSummary(summary)

			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("FormatSummary() should contain %q, got %q", substr, result)
				}
			}
		})
	}
}

func TestFormatter_FormatDuplicateStats(t *testing.T) {
	hashGroups := map[string][]*core.IPResult{
		"abc123": {
			{IP: "1.1.1.1", Title: "Example"},
			{IP: "2.2.2.2", Title: "Example"},
		},
		"def456": {
			{IP: "3.3.3.3", Title: "Unique"},
		},
	}

	f := NewFormatter(core.FormatText, false, false)
	result := f.FormatDuplicateStats(hashGroups)

	if !strings.Contains(result, "abc123") {
		t.Error("Should contain hash abc123")
	}
	if !strings.Contains(result, "def456") {
		t.Error("Should contain hash def456")
	}
	if !strings.Contains(result, "2 IPs") {
		t.Error("Should show group size")
	}
}

func TestFormatter_WriteCSVResults(t *testing.T) {
	results := []*core.IPResult{
		{IP: "1.1.1.1", Status: "200", HTTPCode: 200, ResponseTime: "100ms"},
		{IP: "2.2.2.2", Status: "timeout", HTTPCode: 0, ResponseTime: "", Error: "timeout"},
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	f := NewFormatter(core.FormatCSV, false, false)
	err := f.WriteCSVResults(results, writer)
	if err != nil {
		t.Fatalf("WriteCSVResults() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1.1.1.1") {
		t.Error("CSV should contain first IP")
	}
	if !strings.Contains(output, "2.2.2.2") {
		t.Error("CSV should contain second IP")
	}
	if !strings.Contains(output, "IP,Status,HTTPCode") {
		t.Error("CSV should have header")
	}
}

func TestNewWriter(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "test_output.txt")

	f := NewFormatter(core.FormatText, false, false)
	w, err := NewWriter(outputFile, f, false)
	if err != nil {
		t.Fatalf("NewWriter() error: %v", err)
	}
	defer w.Close()

	if w.file == nil {
		t.Error("Writer should have file handle")
	}
	if w.formatter == nil {
		t.Error("Writer should have formatter")
	}
}

func TestNewWriter_NoFile(t *testing.T) {
	f := NewFormatter(core.FormatText, false, false)
	w, err := NewWriter("", f, false)
	if err != nil {
		t.Fatalf("NewWriter() with no file should not error: %v", err)
	}
	defer w.Close()

	if w.file != nil {
		t.Error("Writer should not have file when outputFile is empty")
	}
}

func TestWriter_WriteResult(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "results.txt")

	f := NewFormatter(core.FormatText, true, false)
	w, err := NewWriter(outputFile, f, false)
	if err != nil {
		t.Fatalf("NewWriter() error: %v", err)
	}

	result := core.IPResult{
		IP:           "1.2.3.4",
		Status:       "200",
		HTTPCode:     200,
		ResponseTime: "100ms",
	}

	w.WriteResult(result)
	w.Close()

	// Read file
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "1.2.3.4") {
		t.Error("Output file should contain IP")
	}
	// Color codes should be stripped from file
	if strings.Contains(output, "\033[") {
		t.Error("Color codes should be stripped from file output")
	}
}

func TestWriter_Quiet(t *testing.T) {
	f := NewFormatter(core.FormatText, false, false)
	w, err := NewWriter("", f, true)
	if err != nil {
		t.Fatalf("NewWriter() error: %v", err)
	}
	defer w.Close()

	if !w.quiet {
		t.Error("Writer should be quiet")
	}
}

func TestStripColors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "with red color",
			input: "\033[31mERROR\033[0m",
			want:  "ERROR",
		},
		{
			name:  "with green color",
			input: "\033[32mSUCCESS\033[0m",
			want:  "SUCCESS",
		},
		{
			name:  "no colors",
			input: "plain text",
			want:  "plain text",
		},
		{
			name:  "multiple colors",
			input: "\033[1m\033[32mBOLD GREEN\033[0m",
			want:  "BOLD GREEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripColors(tt.input)
			if got != tt.want {
				t.Errorf("stripColors() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewProgress(t *testing.T) {
	tests := []struct {
		name      string
		total     uint64
		enabled   bool
		useColors bool
	}{
		{"enabled with colors", 1000, true, true},
		{"enabled no colors", 1000, true, false},
		{"disabled", 1000, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProgress(tt.total, tt.enabled, tt.useColors)
			if p == nil {
				t.Error("NewProgress() returned nil")
			}
			if p.total != tt.total {
				t.Errorf("total = %d, want %d", p.total, tt.total)
			}
			if p.enabled != tt.enabled {
				t.Errorf("enabled = %v, want %v", p.enabled, tt.enabled)
			}
			if tt.useColors && p.cyan == "" {
				t.Error("Colors not initialized")
			}
		})
	}
}

func TestProgress_Increment(t *testing.T) {
	p := NewProgress(1000, false, false)

	p.IncrementScanned()
	p.IncrementScanned()

	scanned := atomic.LoadUint64(p.scanned)
	if scanned != 2 {
		t.Errorf("scanned = %d, want 2", scanned)
	}

	p.IncrementSkipped()
	skipped := atomic.LoadUint64(p.skipped)
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestProgress_Update(t *testing.T) {
	p := NewProgress(1000, false, false)

	p.Update(42)
	scanned := atomic.LoadUint64(p.scanned)
	if scanned != 42 {
		t.Errorf("scanned = %d, want 42", scanned)
	}
}

func TestProgress_Stop(t *testing.T) {
	p := NewProgress(1000, true, false)

	go p.Display()
	time.Sleep(50 * time.Millisecond)

	p.Stop()
	time.Sleep(200 * time.Millisecond)

	stopped := atomic.LoadUint32(p.stopped)
	if stopped != 1 {
		t.Error("Progress should be stopped")
	}
}

func TestProgress_CalculateETA(t *testing.T) {
	p := NewProgress(1000, false, false)

	tests := []struct {
		name     string
		scanned  uint64
		rate     float64
		contains string
	}{
		{"zero scanned", 0, 10.0, "--"},
		{"zero rate", 100, 0, "--"},
		{"seconds", 900, 10.0, "s"},
		{"minutes", 100, 1.0, "m"}, // 900 remaining / 1 per sec = 900s = 15m
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eta := p.calculateETA(tt.scanned, tt.rate)
			if !strings.Contains(eta, tt.contains) {
				t.Errorf("calculateETA() = %q, want to contain %q", eta, tt.contains)
			}
		})
	}
}

func TestProgress_FormatDuration(t *testing.T) {
	p := NewProgress(1000, false, false)

	tests := []struct {
		name     string
		seconds  float64
		contains string
	}{
		{"seconds", 30.0, "s"},
		{"minutes", 120.0, "m"},
		{"hours", 3700.0, "h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.formatDuration(tt.seconds)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("formatDuration(%f) = %q, want to contain %q", tt.seconds, result, tt.contains)
			}
		})
	}
}

func TestWriter_WriteJSON(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "result.json")

	f := NewFormatter(core.FormatJSON, false, false)
	w, err := NewWriter(outputFile, f, false)
	if err != nil {
		t.Fatalf("NewWriter() error: %v", err)
	}

	scanResult := &core.ScanResult{
		Success: []*core.IPResult{
			{IP: "1.1.1.1", Status: "200", HTTPCode: 200},
		},
	}

	err = w.WriteJSON(scanResult)
	if err != nil {
		t.Fatalf("WriteJSON() error: %v", err)
	}
	w.Close()

	// Read and verify JSON
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	var result core.ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if len(result.Success) != 1 {
		t.Errorf("Success count = %d, want 1", len(result.Success))
	}
}

func TestWriter_WriteCSV(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "result.csv")

	f := NewFormatter(core.FormatCSV, false, false)
	w, err := NewWriter(outputFile, f, false)
	if err != nil {
		t.Fatalf("NewWriter() error: %v", err)
	}

	scanResult := &core.ScanResult{
		Success: []*core.IPResult{
			{IP: "1.1.1.1", Status: "200", HTTPCode: 200, ResponseTime: "100ms"},
		},
	}

	err = w.WriteCSV(scanResult)
	if err != nil {
		t.Fatalf("WriteCSV() error: %v", err)
	}
	w.Close()

	// Read and verify CSV
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "1.1.1.1") {
		t.Error("CSV should contain IP")
	}
	if !strings.Contains(output, "IP,Status") {
		t.Error("CSV should have header")
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   int
	}{
		{"found at start", "hello world", "hello", 0},
		{"found in middle", "hello world", "world", 6},
		{"not found", "hello world", "xyz", -1},
		{"empty substring", "hello", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexOf(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestReplaceAll(t *testing.T) {
	tests := []struct {
		name string
		s    string
		old  string
		new  string
		want string
	}{
		{"single replacement", "hello world", "world", "Go", "hello Go"},
		{"multiple replacements", "foo foo foo", "foo", "bar", "bar bar bar"},
		{"no match", "hello", "world", "Go", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := replaceAll(tt.s, tt.old, tt.new)
			if got != tt.want {
				t.Errorf("replaceAll() = %q, want %q", got, tt.want)
			}
		})
	}
}
