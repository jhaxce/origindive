// Package output provides output writing functionality
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jhaxce/origindive/v3/pkg/core"
)

// Writer handles output to console and file
type Writer struct {
	file      *os.File
	formatter *Formatter
	quiet     bool
}

// NewWriter creates a new output writer
func NewWriter(outputFile string, formatter *Formatter, quiet bool) (*Writer, error) {
	w := &Writer{
		formatter: formatter,
		quiet:     quiet,
	}

	if outputFile != "" {
		// Auto-increment if file exists
		originalFile := outputFile
		if _, err := os.Stat(outputFile); err == nil {
			// File exists, find next available number
			base := strings.TrimSuffix(outputFile, filepath.Ext(outputFile))
			ext := filepath.Ext(outputFile)
			for i := 1; ; i++ {
				newName := fmt.Sprintf("%s-%d%s", base, i, ext)
				if _, err := os.Stat(newName); os.IsNotExist(err) {
					outputFile = newName
					fmt.Printf("[*] Output file '%s' exists, using: %s\n", originalFile, outputFile)
					break
				}
			}
		}

		file, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		w.file = file

		// Write CSV header if needed
		if formatter.format == core.FormatCSV {
			fmt.Fprint(file, formatter.FormatCSVHeader())
		}
	}

	return w, nil
}

// WriteHeader writes the scan header
func (w *Writer) WriteHeader(config *core.Config, totalIPs uint64) {
	if w.quiet {
		return
	}

	header := w.formatter.FormatHeader(config, totalIPs)
	if header != "" {
		fmt.Print(header)
	}
}

// WriteResult writes a single result
func (w *Writer) WriteResult(result core.IPResult) {
	formatted := w.formatter.FormatResult(result)

	// Skip empty formatted results (e.g., non-200 when showAll is false)
	if formatted == "" {
		return
	}

	// Write to console
	if !w.quiet {
		fmt.Println(formatted)
	}

	// Write to file
	if w.file != nil {
		// Strip color codes for file output
		clean := stripColors(formatted)
		fmt.Fprintln(w.file, clean)
	}
}

// WriteSummary writes the final summary
func (w *Writer) WriteSummary(summary core.ScanSummary) {
	if w.quiet {
		return
	}

	summaryStr := w.formatter.FormatSummary(summary)
	fmt.Print(summaryStr)
}

// WriteJSON writes complete results as JSON
func (w *Writer) WriteJSON(result *core.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	if w.file != nil {
		_, err = w.file.Write(data)
		return err
	}

	fmt.Println(string(data))
	return nil
}

// WriteCSV writes complete results as CSV
func (w *Writer) WriteCSV(result *core.ScanResult) error {
	if w.file == nil {
		return fmt.Errorf("no output file specified for CSV")
	}

	writer := csv.NewWriter(w.file)
	defer writer.Flush()

	// Combine all results
	allResults := make([]*core.IPResult, 0)
	allResults = append(allResults, result.Success...)
	allResults = append(allResults, result.Redirects...)
	allResults = append(allResults, result.Other...)
	allResults = append(allResults, result.Timeouts...)
	allResults = append(allResults, result.Errors...)

	return w.formatter.WriteCSVResults(allResults, writer)
}

// Close closes the output file
func (w *Writer) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// stripColors removes ANSI color codes from a string
func stripColors(s string) string {
	// Simple implementation - replace common color codes
	replacements := []string{
		"\033[31m", "", // RED
		"\033[32m", "", // GREEN
		"\033[33m", "", // YELLOW
		"\033[34m", "", // BLUE
		"\033[35m", "", // MAGENTA
		"\033[36m", "", // CYAN
		"\033[1m", "", // BOLD
		"\033[0m", "", // NC
	}

	result := s
	for i := 0; i < len(replacements); i += 2 {
		result = replaceAll(result, replacements[i], replacements[i+1])
	}

	return result
}

// replaceAll is a simple string replacement function
func replaceAll(s, old, new string) string {
	// Use stdlib strings.ReplaceAll in production
	// This is simplified for demonstration
	result := ""
	for {
		idx := indexOf(s, old)
		if idx == -1 {
			result += s
			break
		}
		result += s[:idx] + new
		s = s[idx+len(old):]
	}
	return result
}

// indexOf finds the index of a substring
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
