// Package output provides result formatting functionality
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jhaxce/origindive/v3/pkg/core"
)

// Formatter provides result formatting in various formats
type Formatter struct {
	format    core.OutputFormat
	useColors bool
	showAll   bool

	// Colors
	red     string
	green   string
	yellow  string
	blue    string
	cyan    string
	magenta string
	bold    string
	nc      string
}

// NewFormatter creates a new result formatter
func NewFormatter(format core.OutputFormat, useColors bool, showAll bool) *Formatter {
	f := &Formatter{
		format:    format,
		useColors: useColors,
		showAll:   showAll,
	}

	if useColors {
		f.red = "\033[31m"
		f.green = "\033[32m"
		f.yellow = "\033[33m"
		f.blue = "\033[34m"
		f.cyan = "\033[36m"
		f.magenta = "\033[35m"
		f.bold = "\033[1m"
		f.nc = "\033[0m"
	}

	return f
}

// FormatHeader formats the scan header
func (f *Formatter) FormatHeader(config *core.Config, totalIPs uint64) string {
	if f.format != core.FormatText {
		return ""
	}

	// Banner is now handled by main.go printBanner()
	// This function is kept for potential future use
	return ""
}

// FormatResult formats a single IP result
func (f *Formatter) FormatResult(result core.IPResult) string {
	switch f.format {
	case core.FormatJSON:
		data, _ := json.Marshal(result)
		return string(data)
	case core.FormatCSV:
		return fmt.Sprintf("%s,%s,%d,%s", result.IP, result.Status, result.HTTPCode, result.Error)
	default:
		return f.formatTextResult(result)
	}
}

// formatTextResult formats a result in text format with colors
func (f *Formatter) formatTextResult(result core.IPResult) string {
	switch result.Status {
	case "200":
		msg := fmt.Sprintf("%s[+]%s %s --> %s200 OK%s (%s)",
			f.green, f.nc, result.IP, f.green, f.nc, result.ResponseTime)

		// Add title if available
		if result.Title != "" {
			msg += fmt.Sprintf(" | %s\"%s\"%s", f.cyan, result.Title, f.nc)
		}

		// // Add PTR if available
		// if result.PTR != "" {
		// 	msg += fmt.Sprintf(" | %sPTR:%s %s", f.yellow, f.nc, result.PTR)
		// }

		// Add body hash if available (to identify unique responses)
		if result.BodyHash != "" {
			msg += fmt.Sprintf(" [%s%s%s]", f.magenta, result.BodyHash, f.nc)
		}

		// Add redirect chain if available
		if len(result.RedirectChain) > 0 {
			msg += fmt.Sprintf("\n%s    Redirect chain:%s", f.yellow, f.nc)
			for i, redirect := range result.RedirectChain {
				msg += fmt.Sprintf("\n      %d. %s", i+1, redirect)
			}
		}

		return msg
	case "3xx":
		if !f.showAll {
			return ""
		}
		msg := fmt.Sprintf("%s[>]%s %s --> HTTP %d (Redirect)",
			f.yellow, f.nc, result.IP, result.HTTPCode)

		// Add redirect chain if available
		if len(result.RedirectChain) > 0 {
			msg += fmt.Sprintf("\n%s    Redirect chain:%s", f.yellow, f.nc)
			for i, redirect := range result.RedirectChain {
				msg += fmt.Sprintf("\n      %d. %s", i+1, redirect)
			}
		}

		return msg
	case "timeout":
		if !f.showAll {
			return ""
		}
		return fmt.Sprintf("%s[~]%s %s --> Timeout",
			f.blue, f.nc, result.IP)
	case "error":
		if !f.showAll {
			return ""
		}
		return fmt.Sprintf("%s[-]%s %s --> Error: %s",
			f.red, f.nc, result.IP, result.Error)
	default:
		if !f.showAll {
			return ""
		}
		return fmt.Sprintf("%s[~]%s %s --> HTTP %d",
			f.cyan, f.nc, result.IP, result.HTTPCode)
	}
}

// FormatSummary formats the final scan summary
func (f *Formatter) FormatSummary(summary core.ScanSummary) string {
	switch f.format {
	case core.FormatJSON:
		data, _ := json.MarshalIndent(summary, "", "  ")
		return string(data)
	default:
		return f.formatTextSummary(summary)
	}
}

// FormatDuplicateStats formats duplicate hash statistics
func (f *Formatter) FormatDuplicateStats(hashGroups map[string][]*core.IPResult) string {
	if len(hashGroups) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════\n")
	sb.WriteString(f.bold + "Content Hash Analysis\n" + f.nc)
	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════" + f.nc + "\n")

	// Sort by group size (largest first)
	type hashGroup struct {
		hash    string
		count   int
		results []*core.IPResult
		title   string
	}
	var groups []hashGroup
	for hash, results := range hashGroups {
		title := ""
		if len(results) > 0 && results[0].Title != "" {
			title = results[0].Title
		}
		groups = append(groups, hashGroup{hash, len(results), results, title})
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].count > groups[j].count
	})

	// Show statistics
	sb.WriteString(fmt.Sprintf("%s[*]%s Total unique responses: %s%d%s\n", f.bold, f.nc, f.green, len(groups), f.nc))
	sb.WriteString("\n")

	// Show each group
	for i, g := range groups {
		if g.count == 1 {
			if g.title != "" {
				sb.WriteString(fmt.Sprintf("%s[✓] Hash %s%s%s (%s%d IP%s) - UNIQUE RESPONSE: %s\"%s\"%s\n",
					f.green, f.magenta, g.hash, f.nc, f.green, g.count, f.nc, f.cyan, g.title, f.nc))
			} else {
				sb.WriteString(fmt.Sprintf("%s[✓] Hash %s%s%s (%s%d IP%s) - UNIQUE RESPONSE%s\n",
					f.green, f.magenta, g.hash, f.nc, f.green, g.count, f.nc, f.nc))
			}
		} else {
			if g.title != "" {
				sb.WriteString(fmt.Sprintf("%s[~] Hash %s%s%s (%s%d IPs%s) - Shared response: %s\"%s\"%s\n",
					f.yellow, f.magenta, g.hash, f.nc, f.yellow, g.count, f.nc, f.cyan, g.title, f.nc))
			} else {
				sb.WriteString(fmt.Sprintf("%s[~] Hash %s%s%s (%s%d IPs%s) - Shared response:%s\n",
					f.yellow, f.magenta, g.hash, f.nc, f.yellow, g.count, f.nc, f.nc))
			}
		}

		// Show first 5 IPs in group
		maxShow := 5
		if g.count < maxShow {
			maxShow = g.count
		}
		for j := 0; j < maxShow; j++ {
			sb.WriteString(fmt.Sprintf("    %s%s%s\n", f.cyan, g.results[j].IP, f.nc))
		}
		if g.count > maxShow {
			sb.WriteString(fmt.Sprintf("    ... and %d more\n", g.count-maxShow))
		}

		if i < len(groups)-1 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════" + f.nc + "\n")
	return sb.String()
}

// formatTextSummary formats summary in text format
func (f *Formatter) formatTextSummary(summary core.ScanSummary) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════\n")
	sb.WriteString(f.bold + "Scan Results Summary\n" + f.nc)
	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════" + f.nc + "\n")

	// Show 200 OK count (no individual IP list)
	sb.WriteString(fmt.Sprintf("%s[+] 200 OK:%s %s%d%s\n", f.green, f.nc, f.green, summary.SuccessCount, f.nc))

	// Possible origin hosts discovered during verification
	// Only display related possible-origin IPs (omit "related:" label and any "other" IPs)
	if len(summary.PossibleOriginRelatedIPs) > 0 {
		sb.WriteString(fmt.Sprintf("%s[?]%s Possible origin(s): ", f.bold, f.nc))
		for i, ip := range summary.PossibleOriginRelatedIPs {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(f.green + ip + f.nc)
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("%s[*]%s Total Scanned: %s%d%s\n", f.bold, f.nc, f.bold, summary.ScannedIPs, f.nc))

	if summary.SkippedIPs > 0 {
		sb.WriteString(fmt.Sprintf("%s[S]%s WAF IPs Skipped: %s%d%s\n", f.yellow, f.nc, f.yellow, summary.SkippedIPs, f.nc))
	}

	sb.WriteString(fmt.Sprintf("%s[T]%s Duration: %s%.2fs%s\n", f.blue, f.nc, f.blue, summary.Duration.Seconds(), f.nc))

	if summary.Duration.Seconds() > 0 {
		rate := float64(summary.ScannedIPs) / summary.Duration.Seconds()
		sb.WriteString(fmt.Sprintf("%s[R]%s Scan Rate: %s%.2f IPs/s%s\n", f.magenta, f.nc, f.magenta, rate, f.nc))
	}

	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════" + f.nc + "\n\n")

	return sb.String()
}

// FormatCSVHeader returns CSV header row
func (f *Formatter) FormatCSVHeader() string {
	return "IP,Status,HTTPCode,ResponseTime,Error\n"
}

// WriteCSVResults writes results in CSV format
func (f *Formatter) WriteCSVResults(results []*core.IPResult, writer *csv.Writer) error {
	// Write header
	if err := writer.Write([]string{"IP", "Status", "HTTPCode", "ResponseTime", "Error"}); err != nil {
		return err
	}

	// Write results
	for _, r := range results {
		record := []string{
			r.IP,
			r.Status,
			fmt.Sprintf("%d", r.HTTPCode),
			r.ResponseTime,
			r.Error,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}
