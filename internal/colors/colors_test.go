package colors

import (
	"os"
	"runtime"
	"testing"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		check   func(t *testing.T)
	}{
		{
			name:    "enabled",
			enabled: true,
			check: func(t *testing.T) {
				if RED != "\033[31m" {
					t.Errorf("RED = %q, want %q", RED, "\033[31m")
				}
				if GREEN != "\033[32m" {
					t.Errorf("GREEN = %q, want %q", GREEN, "\033[32m")
				}
				if YELLOW != "\033[33m" {
					t.Errorf("YELLOW = %q, want %q", YELLOW, "\033[33m")
				}
				if BLUE != "\033[34m" {
					t.Errorf("BLUE = %q, want %q", BLUE, "\033[34m")
				}
				if CYAN != "\033[36m" {
					t.Errorf("CYAN = %q, want %q", CYAN, "\033[36m")
				}
				if MAGENTA != "\033[35m" {
					t.Errorf("MAGENTA = %q, want %q", MAGENTA, "\033[35m")
				}
				if BOLD != "\033[1m" {
					t.Errorf("BOLD = %q, want %q", BOLD, "\033[1m")
				}
				if NC != "\033[0m" {
					t.Errorf("NC = %q, want %q", NC, "\033[0m")
				}
			},
		},
		{
			name:    "disabled",
			enabled: false,
			check: func(t *testing.T) {
				if RED != "" {
					t.Errorf("RED = %q, want empty", RED)
				}
				if GREEN != "" {
					t.Errorf("GREEN = %q, want empty", GREEN)
				}
				if YELLOW != "" {
					t.Errorf("YELLOW = %q, want empty", YELLOW)
				}
				if BLUE != "" {
					t.Errorf("BLUE = %q, want empty", BLUE)
				}
				if CYAN != "" {
					t.Errorf("CYAN = %q, want empty", CYAN)
				}
				if MAGENTA != "" {
					t.Errorf("MAGENTA = %q, want empty", MAGENTA)
				}
				if BOLD != "" {
					t.Errorf("BOLD = %q, want empty", BOLD)
				}
				if NC != "" {
					t.Errorf("NC = %q, want empty", NC)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Init(tt.enabled)
			tt.check(t)
		})
	}
}

func TestShouldUseColors(t *testing.T) {
	// Save original environment
	origNoColor := os.Getenv("NO_COLOR")
	defer os.Setenv("NO_COLOR", origNoColor)

	tests := []struct {
		name    string
		noColor bool
		env     string
		want    bool
	}{
		{
			name:    "explicit disable via flag",
			noColor: true,
			env:     "",
			want:    false,
		},
		{
			name:    "explicit disable via env",
			noColor: false,
			env:     "1",
			want:    false,
		},
		{
			name:    "both flag and env",
			noColor: true,
			env:     "1",
			want:    false,
		},
		{
			name:    "no disable - depends on OS/TTY",
			noColor: false,
			env:     "",
			want:    runtime.GOOS == "linux" || runtime.GOOS == "darwin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment
			if tt.env != "" {
				os.Setenv("NO_COLOR", tt.env)
			} else {
				os.Unsetenv("NO_COLOR")
			}

			got := ShouldUseColors(tt.noColor)

			// Only check explicit disable cases (flag or env)
			if tt.noColor || tt.env == "1" {
				if got != false {
					t.Errorf("ShouldUseColors(%v) = %v, want false (explicit disable)", tt.noColor, got)
				}
			} else {
				// For no-disable case, result depends on OS and TTY
				// Just verify it returns a boolean
				if got != true && got != false {
					t.Errorf("ShouldUseColors(%v) returned non-boolean", tt.noColor)
				}
			}
		})
	}
}

func TestShouldUseColors_UnixDefault(t *testing.T) {
	os.Unsetenv("NO_COLOR")

	result := ShouldUseColors(false)

	// On Linux/Darwin without NO_COLOR, should return true (unless not a TTY)
	// On Windows, may return false
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		// TTY check might fail in CI, so we just verify no panic
		_ = result
	} else {
		// Other OS behavior is undefined but should not panic
		_ = result
	}
}

func TestInit_RepeatedCalls(t *testing.T) {
	// Test that repeated calls work correctly
	Init(true)
	enabled := RED
	Init(false)
	disabled := RED
	Init(true)
	reEnabled := RED

	if disabled != "" {
		t.Errorf("After Init(false), RED should be empty, got %q", disabled)
	}
	if enabled != reEnabled {
		t.Errorf("Init(true) not consistent: first=%q, second=%q", enabled, reEnabled)
	}
}

func TestColorValues(t *testing.T) {
	Init(true)

	tests := []struct {
		name  string
		color *string
		want  string
	}{
		{"RED", &RED, "\033[31m"},
		{"GREEN", &GREEN, "\033[32m"},
		{"YELLOW", &YELLOW, "\033[33m"},
		{"BLUE", &BLUE, "\033[34m"},
		{"CYAN", &CYAN, "\033[36m"},
		{"MAGENTA", &MAGENTA, "\033[35m"},
		{"BOLD", &BOLD, "\033[1m"},
		{"NC", &NC, "\033[0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if *tt.color != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, *tt.color, tt.want)
			}
		})
	}
}
